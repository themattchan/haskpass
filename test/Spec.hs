{-# LANGUAGE OverloadedStrings #-}

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.Aeson as A
import AgileKeychain
import Data.Maybe
import qualified Data.ByteString as B

main :: IO ()
main = defaultMain $
   testCase "Raw Key Decoder" $ do
--    let myEncData = "U2FsdGVkX18se9ET2syAK2TEsRnmZtHq2mSad4W1egtnrLpaYtVdtqGv6ZWVwRb0h\\/6Lt7FgHDhe0dG6qmOzWi8r0\\/6RBuC62RNmjBCYs8lolcYEFGIaECyKSIp+UfsPJWmGTViV0JBElphOPWkEEzUhHK4rsifQ2OthQ7cirRYnVDfl9NtUUEw1a3fdImjN63svEK+OiGdCReOrdaS\\/3s8rhDq9EkSSPmSu0BXz8tD8EFxN5mAww+EOjvRlrcNC825SKbpQZTq61loNEX2hf54hIg+Xr45xSUHueeoSDBX2RGCliW\\/0ejiQAykOtWfQOZf6lbp8OTTat6AQNki1\\/4WM0AEKsBOrQax7rn9G4LHOvsQeK88XQGHfJeQDR1NYLHSOReUkbKEF7KTOWp5ycqXvcgtj5ozyMLKhNCJ7a98ZY002EkgdGVZtlmgDRuqkWqDxeB8fmjLkO6EzlfK6VwgKAb0+2A5In8eUnNAvByhBm3Pz07B4A5sLCth9\\/Wiq7uOkA2Bjc2lps25C1bwyIpksJ9Z3Gxv5OvoClF3yEhKctopBdN5Qbgsp+CSsspLum9M2P\\/06gzJ7xIv7BYfVLRc8U79zF4XjY9h0i1GJD04x4eMwhpRsOhmwYnDxECplHRevkwIYSZrRFnpg\\/1w5apO8Ptj+cFtF3cJTLLo9GPFMj2c\\/tBxCw2PG7fZmBxkXhBC9Y8+LatxuCni\\/Zl61b2BWWpAAtZ7oersVCWun5q+StiJEeOdGlFYdv9j4jBxbWcU\\/O1vvW4CcQ2LUynwZy7k0HDu\\/jbdI4ezyE9Vo0RK1CAbuVCHtI0FiOCMI1dbGpB\\/smprroryRBDjuerEZT7n+oyk0sQDag5HAZntPDAFYF3+weKsAvag64afVR2UL5t2jsEQlwPUuxo\\/crNC2l7qxzoGBy5N+J9\\/TL+9gZCrOFAqDJNpFBUQzWVZzdPBsb6kp+WmsiiAsYx6dWPH\\/B7lGe2JpRLMfxBG1boynXchbWzFa6L+zn\\/3HyHcqttALNFkuCD88TA7EUrh4zJWr3SvaBvGHc\\/7dVLJtGyiVGNxVccXLSjd9nFsxlS9jqH3h6DfsBUWlb\\/mTeWFYBD4eq4CWY1rhG9MzDHUQMLOAzUt6QKDqN7TmVV+JUqwe7m6DhapbEpmbOcKUnm7MhcAz4WckwtmD5GlNh5QNU6p7Dom6mBlfV9ZHwkEeG1\\/b0J9QUTa3o4wGZQQuM\\/+LQKgQbrQCEEP8Rs\\/VDppcgkzHR7C\\/G1OlypPBy2Ht0nAtMbcIFmjANtUVjz8zwkGFhLEhhfGqA5u5uugozubnWkn2r+X0QO7sjLWT+u4oNrs5GqFyEwpWQ1ndwMplm0UZICTGDVsCJYKoxqFFuCDaqUZ4LIUJAxT4CbreiIM0I1SYe0Sm"

--    print $ decodeEncData myEncData

    let rawKey1 = "{\"data\":\"my precious data\",\"validation\":\"my valid validation\",\"level\":\"SL3\",\"identifier\":\"8AD42DD06B79476CB56AD44EB0868870\",\"iterations\":100000}"

    A.decode rawKey1 @=? Just (RawKey
        { rawKeyData       = "my precious data"
        , rawKeyIdentifier = "8AD42DD06B79476CB56AD44EB0868870"
        , rawKeyValidation = "my valid validation"
        , rawKeyIterations = 100000
        , rawKeyLevel      = SL3
        } :: RawKey String)

    demoKeychain <- B.readFile (keychainFile "demo.agilekeychain")
    isJust (readKeychain demoKeychain "demo") @=? True
