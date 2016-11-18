module AgileKeychain where

import qualified Data.Map as M
import qualified Data.Set as S
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL

import System.FilePath
import OpenSSL.EVP.Digest (pkcs5_pbkdf2_hmac_sha1)
import qualified Network.URL as URL
import qualified Data.Aeson as JSON

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
  deriving (Show,Eq)

data AgileKeychainMasterKey = AgileKeychainMasterKey
  { mk_Level :: KeyLevel
  , mk_id    :: UUID
  , mk_data  :: B.ByteString
  }

data AgileKeychain = AgileKeychain
  { ak_level3Key  :: AgileKeychainMasterKey
  , ak_level5Key  :: AgileKeychainMasterKey
  , ak_vaultPath  :: FilePath
  , ak_vaultTitle :: String
  , ak_items      :: S.Set KeychainItem
  } deriving (Show, Eq)

type ErrorMsg = String

loadKeychain :: FilePath -> IO (Either ErrorMsg AgileKeychain)
loadKeychain kcLoc = do
  mayRawKeys <- JSON.decodeEither <$> BL.readFile $ kcLoc </> "/data/default/encryptionKeys.js"
  return $ do
    keys <- mayRawKeys
