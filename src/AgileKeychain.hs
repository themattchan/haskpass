{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE LambdaCase        #-}

module AgileKeychain where

import Control.Arrow ((>>>))
import Control.Monad
import Control.Monad.Trans.Class
import Control.Monad.Trans.Maybe

import Data.Maybe
import qualified Data.Map as M
import qualified Data.Set as S
import qualified Data.Text as T
import qualified Data.Vector as V
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL

import System.FilePath

import qualified Data.Aeson as A
import qualified Data.Aeson.Types as A
import Data.Aeson ((.:), (.:?), (.!=))

import qualified OpenSSL.EVP.Base64 as SSL (decodeBase64BS)
import qualified OpenSSL.EVP.Digest as SSL (pkcs5_pbkdf2_hmac_sha1)

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
  { mk_level :: KeyLevel
  , mk_id    :: UUID
  , mk_data  :: B.ByteString
  } deriving (Show, Eq)

data AgileKeychain = AgileKeychain
  { ak_vaultTitle :: String
  , ak_vaultPath  :: FilePath
  , ak_level3Key  :: AgileKeychainMasterKey
  , ak_level5Key  :: AgileKeychainMasterKey
  , ak_items      :: S.Set AgileKeychainItem
  } deriving (Show)

{-@ type Salt = { v :: B.ByteString | bslen v == 8 } @-}
type Salt = B.ByteString

type DecodedData = (Maybe Salt, B.ByteString)

-- | A single undecrypted key entry in the list from 'encryptedKeys.js'
data RawKey = RawKey
  { rawKeyData       :: DecodedData
  , rawKeyIdentifier :: String
  , rawKeyValidation :: String
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
    rawKeyData       <- orFail errKeyData =<< decodeEncData . B.pack <$> jsonObj .: "data"
    rawKeyIdentifier <- jsonObj .: "identifier"
    rawKeyValidation <- jsonObj .: "validation"
    rawKeyIterations <- max 1000 <$> jsonObj .:? "iterations" .!= 0
    rawKeyLevel      <- jsonObj .: "level"
    return RawKey{..}
    where
      errKeyData  = "bad key data"

decodeEncData :: B.ByteString -> Maybe DecodedData
decodeEncData dat
  | B.length decoded < 8 = Nothing
  | hasSalt              = Just (Just salt, B.drop 16 decoded)
  | otherwise            = Just (Nothing, decoded)
  where
    decoded = SSL.decodeBase64BS dat
    hasSalt = "Salted__" `B.isPrefixOf` decoded
    salt    = (B.take 8 . B.drop 8) decoded

decryptRawKeyData :: String -> RawKey -> AgileKeychainMasterKey
decryptRawKeyData masterPass RawKey{..} =
  undefined
