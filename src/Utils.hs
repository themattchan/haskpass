module Utils where

import qualified Control.Monad.Fail as Fail

type ErrorMsg = String

note :: e -> Maybe a -> Either e a
note _ (Just a) = Right a
note e Nothing = Left e

orFail :: Fail.MonadFail m => ErrorMsg -> Maybe a -> m a
orFail s Nothing = Fail.fail s
orFail s (Just x) = return x
