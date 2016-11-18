{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

module AgileKeychain where

import Control.Monad.Trans.Class
import Control.Monad.Trans.Maybe

import qualified Data.Map as M
import qualified Data.Set as S
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

--import Data.Attoparsec.ByteString

--------------------------------------------------------------------------------
-- * Types
--------------------------------------------------------------------------------

type ErrorMsg = String

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

newtype RawKeyData = RawKeyData (DecodedData, String, String, Int, KeyLevel)

--------------------------------------------------------------------------------
-- * Keychain parsing
--------------------------------------------------------------------------------

-- readKeychain :: FilePath -> IO (Either ErrorMsg AgileKeychain)
readKeychain kcLoc masterPass =
  undefined <$> B.readFile keychainFile
  where
    keychainFile = kcLoc </> "/data/default/encryptionKeys.js"

--    errNoList = "Could not find list of keys in keychain"

    readRawKeyJson v = do
--      encKeys <- A.json
      keyList <- A.withObject "list of keys" (.: "list") v
      parsedKeys <- A.withArray "a single key" (mapM parseOneKey . V.toList) keyList
      return parsedKeys


parseKeyLevel :: String -> Maybe KeyLevel
parseKeyLevel "SL3" = Just SL3
parseKeyLevel "SL5" = Just SL5
parseKeyLevel _     = Nothing

parseOneKey :: A.Value -> A.Parser (Maybe RawKeyData)
parseOneKey jsonVal = runMaybeT $ do
  jsonObj       <- lift   $ A.withObject "get json object" return jsonVal
  keyData       <- MaybeT $ decodeEncData . B.pack <$> jsonObj .: "data"
  keyId         <- lift   $ jsonObj .: "identifier"
  keyValidation <- lift   $ jsonObj .: "validation"
  keyIterations <- lift   $ max 1000 <$> jsonObj .:? "iterations" .!= 0
  keyLevel      <- MaybeT $ parseKeyLevel <$> jsonObj .: "level"
  return $ RawKeyData(keyData, keyId, keyValidation, keyIterations, keyLevel)

decodeEncData :: B.ByteString -> Maybe DecodedData
decodeEncData dat
  | B.length decoded < 8 = Nothing
  | hasSalt              = Just (Just salt, B.drop 16 decoded)
  | otherwise            = Just (Nothing, decoded)
  where
    decoded = SSL.decodeBase64BS dat
    hasSalt = "Salted__" `B.isPrefixOf` decoded
    salt    = (B.take 8 . B.drop 8) decoded
