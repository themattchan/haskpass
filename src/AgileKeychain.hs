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
import qualified Data.Map as M
import qualified Data.Set as S
import qualified Data.Text as T
import qualified Data.Vector as V
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL

import System.FilePath
import System.IO.Unsafe

import qualified Data.Aeson as A
import qualified Data.Aeson.Types as A
import Data.Aeson ((.:), (.:?), (.!=))

import qualified OpenSSL            as SSL (withOpenSSL)
import qualified OpenSSL.EVP.Base64 as SSL (decodeBase64BS)
import qualified OpenSSL.EVP.Digest as SSL (pkcs5_pbkdf2_hmac_sha1)
import qualified OpenSSL.EVP.Cipher as SSL (Cipher(..), CryptoMode(..),
                                            getCipherByName, cipherBS)

import qualified Network.URL as URL


import Utils
--import Data.Attoparsec.ByteString

--------------------------------------------------------------------------------
-- * Types
--------------------------------------------------------------------------------

data KeyLevel = SL3 | SL5
  deriving (Show,Eq, Bounded, Enum)

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
  , ak_masterKeys :: M.Map KeyLevel AgileKeychainMasterKey
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

readKeychain :: FilePath -> String ->  IO (Maybe AgileKeychain)
readKeychain kcLoc masterPass =
  undefined <$> B.readFile keychainFile
  where
    keychainFile = kcLoc </> "/data/default/encryptionKeys.js"

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
                  -> IO (Maybe (M.Map KeyLevel AgileKeychainMasterKey))
decryptRawKeyData masterPass RawKey{..} = SSL.withOpenSSL $ do
  Just aes128cbc <- SSL.getCipherByName "aes-128-cbc"
  decrypted <- decryptedKeyData aes128cbc
  return $ M.singleton rawKeyLevel AgileKeychainMasterKey{..}
  where
    (rawSalt, rawData) = rawKeyData
    salt      = fromMaybe mempty rawSalt

    masterKeyLength = 32
    masterKey = SSL.pkcs5_pbkdf2_hmac_sha1
                  masterPass salt rawKeyIterations masterKeyLength

    decryptedKeyData algo =
      SSL.cipherBS algo aesSymmKey aesIv SSL.Decrypt rawData
      where
        aesSymmKey = B.take 16 masterKey
        aesIv      = B.drop 16 masterKey

--    validationKeys
