{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE LambdaCase        #-}

module AgileKeychain where

import Control.Arrow ((>>>))
import Control.Monad
import Control.Monad.Trans.Class
import Control.Monad.Trans.Maybe
import Control.Monad.Trans.RWS

import Data.Maybe
import Data.Monoid
import Data.Foldable
import Data.Traversable
import qualified Data.Map as M
import qualified Data.Set as S
import qualified Data.Text as T
import qualified Data.Vector as V
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL

import System.Directory
import System.FilePath
import System.IO.Unsafe

import qualified Data.Aeson as A
import qualified Data.Aeson.Types as A
import Data.Aeson ((.:), (.:?), (.!=))
import qualified Data.Attoparsec as AP

import qualified OpenSSL              as SSL
  (withOpenSSL)
import qualified OpenSSL.EVP.Base64   as SSL
  (decodeBase64BS)
import qualified OpenSSL.EVP.Internal as SSL
  (digestStrictly, digestUpdateBS, digestFinalBS)
import qualified OpenSSL.EVP.Digest   as SSL
  (pkcs5_pbkdf2_hmac_sha1, getDigestByName)
import qualified OpenSSL.EVP.Cipher   as SSL
  (Cipher(..), CryptoMode(..), getCipherByName, cipherBS)

import qualified Network.URL as URL


import Utils
--import Data.Attoparsec.ByteString

--------------------------------------------------------------------------------
-- * Types
--------------------------------------------------------------------------------

data KeyLevel = SL3 | SL5
  deriving (Show,Eq, Bounded, Enum, Ord)

newtype UUID
  = UUID { getUUID :: String }
  deriving (Show, Eq)

data Value = Password String
           | Plaintext String
           deriving (Show, Eq)

type Section = String

data ItemField = ItemField
  { name    :: String
  , value   :: Value
  , valtype :: String      -- TODO make this typed
  } deriving (Show, Eq)

data AgileKeychainItem = AgileKeychainItem
  { itemTitle :: String
  , itemUUID  :: UUID
  , category  :: String
  , folder    :: String
  , fields    :: M.Map Section [ItemField]
  , links     :: [URL.URL]
  , website   :: URL.URL
  , notes     :: String
  } deriving (Show)

-- | A decrypted master key
data AgileKeychainMasterKey = AgileKeychainMasterKey
  { mk_level :: KeyLevel -- this is redundant
  , mk_id    :: UUID
  , mk_data  :: B.ByteString
  } deriving (Show, Eq)

data AgileKeychain = AgileKeychain
  { ak_vaultTitle :: String
  , ak_vaultPath  :: FilePath
  , ak_level3Key :: AgileKeychainMasterKey
  , ak_level5Key :: AgileKeychainMasterKey
--  , ak_masterPassword :: String
--  , ak_items      :: S.Set AgileKeychainItem
  } deriving (Show)

type AgileKeychainT m = RWST AgileKeychain () (S.Set AgileKeychainItem) m

type AgileKeychainM = AgileKeychainT IO

{-@ type Salt = { v :: B.ByteString | bslen v == 8 } @-}
type Salt = B.ByteString

type DecodedData = (Maybe Salt, B.ByteString)

-- | A single undecrypted key entry in the list from 'encryptedKeys.js'
data RawKey = RawKey
  { rawKeyData       :: DecodedData
  , rawKeyIdentifier :: String
  , rawKeyValidation :: DecodedData
  , rawKeyIterations :: Int
  , rawKeyLevel      :: KeyLevel
  } deriving Show

--------------------------------------------------------------------------------
-- * Keychain parsing
--------------------------------------------------------------------------------

readKeychain :: FilePath -> B.ByteString ->  IO (Maybe AgileKeychain)
readKeychain ak_vaultPath masterPass = do
  putStrLn keychainFile
  getCurrentDirectory  >>= putStrLn
  rawEncryptionKeysJs <- B.readFile keychainFile
  print  rawEncryptionKeysJs
  let mRawJson = AP.maybeResult . AP.parse A.json $ rawEncryptionKeysJs
  case mRawJson >>= A.parseMaybe A.parseJSON :: Maybe [RawKey] of
    Just rawKeys -> do
      print rawKeys
      masterKeys <- fold <$> mapM (decryptRawKeyData masterPass) rawKeys
      let ak_level5Key = masterKeys M.! SL5
          ak_level3Key = masterKeys M.! SL3
      return $ Just $ AgileKeychain{..}
    _ -> do
      putStrLn "fail"
      return Nothing
  where
    ak_vaultTitle = "vault"
    keychainFile = ak_vaultPath </> "data/default/encryptionKeys.js"

instance A.FromJSON [RawKey] where
  parseJSON
    =  A.withObject "list of keys" (.: "list")
   >=> A.withArray  "a single key" (mapM A.parseJSON . V.toList)

instance A.FromJSON KeyLevel where
  parseJSON = A.withText "key level"
    (\case
        "SL3" -> return SL3
        "SL5" -> return SL5
        _     -> fail "cannot parse key level")

instance A.FromJSON RawKey where
  parseJSON jsonVal = do
    jsonObj          <- A.withObject "get json object" return jsonVal
    rawKeyData       <- parseKeyData $ jsonObj .: "data"
    rawKeyIdentifier <- jsonObj .: "identifier"
    rawKeyValidation <- parseKeyData $ jsonObj .: "validation"
    rawKeyIterations <- max 1000 <$> jsonObj .:? "iterations" .!= 0
    rawKeyLevel      <- jsonObj .: "level"
    return RawKey{..}
    where
      parseKeyData = (>>= orFail errKeyData) . fmap (decodeEncData . B.pack)
      errKeyData   = "bad key data"

decodeEncData :: B.ByteString -> Maybe DecodedData
decodeEncData dat
  | B.length decoded < 8 = Nothing
  | hasSalt              = Just (Just salt, B.drop 16 decoded)
  | otherwise            = Just (Nothing, decoded)
  where
    decoded = SSL.decodeBase64BS dat
    hasSalt = "Salted__" `B.isPrefixOf` decoded
    salt    = (B.take 8 . B.drop 8) decoded

decryptRawKeyData :: B.ByteString -> RawKey
                  -> IO (M.Map KeyLevel AgileKeychainMasterKey)
decryptRawKeyData masterPass RawKey{..} = SSL.withOpenSSL $ do
  Just aes128cbc  <- SSL.getCipherByName "aes-128-cbc"
  decryptedKey    <- decryptKey aes128cbc
  (valKey, valIv) <- getValidationKeys decryptedKey
  validation      <- SSL.cipherBS aes128cbc valKey valIv SSL.Decrypt valData
  if (decryptedKey == validation) then
    return $ M.singleton rawKeyLevel
      (AgileKeychainMasterKey rawKeyLevel (UUID rawKeyIdentifier) decryptedKey)
  else
    return M.empty
  where
    (rawSalt, rawData) = rawKeyData
    (valSalt, valData) = rawKeyValidation
    salt               = fromMaybe mempty rawSalt

    masterKeyLength = 32

    masterKey = SSL.pkcs5_pbkdf2_hmac_sha1
                  masterPass salt rawKeyIterations masterKeyLength

    decryptKey algo =
      SSL.cipherBS algo aesSymmKey aesIv SSL.Decrypt rawData
      where
        aesSymmKey = B.take 16 masterKey
        aesIv      = B.drop 16 masterKey

    getValidationKeys decryptedPass = do
      Just md5 <-  SSL.getDigestByName "MD5"
      ctx1 <- SSL.digestStrictly md5 decryptedPass
      when (isJust valSalt) $ do
        SSL.digestUpdateBS ctx1 (fromJust valSalt)
      keyOut <- SSL.digestFinalBS ctx1

      ivOut <- case valSalt of
        Just salt -> do
          ctx2 <- SSL.digestStrictly md5 (B.take 16 keyOut)
          SSL.digestUpdateBS ctx2 decryptedPass
          SSL.digestUpdateBS ctx2 salt
          ivOut <- SSL.digestFinalBS ctx2
          return ivOut
        Nothing -> return mempty

      return (keyOut, ivOut)
