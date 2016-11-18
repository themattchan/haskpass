{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module AgileKeychain where

import qualified Data.Map as M
import qualified Data.Set as S
import qualified Data.Vector as V
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL

import Control.Monad.Trans.Class
import Control.Monad.Trans.Maybe

import System.FilePath

import OpenSSL.EVP.Base64
import OpenSSL.EVP.Digest (pkcs5_pbkdf2_hmac_sha1)

import qualified Network.URL as URL
import qualified Data.Aeson as A
import qualified Data.Aeson.Types as A
import Data.Aeson ((.:), (.:?), (.!=))
--import Data.Attoparsec.ByteString

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
  , valtype :: String
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

data KeyLevel = SL3 | SL5
  deriving (Show,Eq, Bounded, Enum)

parseKeyLevel :: String -> Maybe KeyLevel
parseKeyLevel "SL3" = Just SL3
parseKeyLevel "SL5" = Just SL5
parseKeyLevel _     = Nothing


data AgileKeychainMasterKey = AgileKeychainMasterKey
  { mk_Level :: KeyLevel
  , mk_id    :: UUID
  , mk_data  :: B.ByteString
  } deriving (Show, Eq)

data AgileKeychain = AgileKeychain
  { ak_level3Key  :: AgileKeychainMasterKey
  , ak_level5Key  :: AgileKeychainMasterKey
  , ak_vaultPath  :: FilePath
  , ak_vaultTitle :: String
  , ak_items      :: S.Set AgileKeychainItem
  } deriving (Show)


type ErrorMsg = String

{-@ type Salt = { v :: B.ByteString | bslen v == 8 @-}
type Salt = B.ByteString
type RawKeyData = (Maybe Salt, B.ByteString)

parseEncData :: B.ByteString -> Maybe RawKeyData
parseEncData dat =
  if B.length decoded < 8
  then Nothing
  else Just (salt, decodedData)
  where
    decoded = decodeBase64BS dat
    hasSalt = "Salted__" `B.isPrefixOf` decoded
    salt
      | hasSalt = Just ((B.take 8 . B.drop 8) decoded)
      | otherwise = Nothing
    decodedData
      | hasSalt = B.drop 16 decoded
      | otherwise = decoded

-- readKeychain :: FilePath -> IO (Either ErrorMsg AgileKeychain)
readKeychain kcLoc masterPass =
  undefined <$> B.readFile keychainFile
  where
    keychainFile = kcLoc </> "/data/default/encryptionKeys.js"

    errNoList = "Could not find list of keys in keychain"

    readRawKeyJson v = do
--      encKeys <- A.json
      keyList <- A.withObject "list of keys" (.: "list") v
      parsedKeys <- A.withArray "a single key" (mapM parseOneKey . V.toList) keyList
      return parsedKeys

    parseOneKey :: A.Value -> A.Parser (Maybe (RawKeyData, B.ByteString, B.ByteString, B.ByteString, KeyLevel))
    parseOneKey jsonVal = runMaybeT $ do
      keyData       <- MaybeT $ parseEncData <$> jsonVal .: "data"
      keyId         <- lift $ jsonVal .: "identifier"
      keyValidation <- lift $ jsonVal .: "validation"
      keyIterations <- lift $ max 1000 <$> jsonVal .:? "iterations" .!= 0
      keyLevel      <- MaybeT $ parseKeyLevel <$> jsonVal .: "level"
      return (keyData, keyId, keyValidation, keyIterations, keyLevel)
