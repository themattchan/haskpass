{-# LANGUAGE OverloadedStrings #-}

--import Test.Tasty
--import Test.Tasty.HUnit

import AgileKeychain

main :: IO ()
main = do
  key <- readKeychain "demo.agilekeychain" "demo"
  case key of
    Just x -> putStrLn "GOOD"
    Nothing -> putStrLn "BAD"
