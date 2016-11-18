module GUI where

import Control.Concurrent
import Control.Monad
import Control.Monad.IO.Class

import Graphics.UI.Gtk hiding (disconnect)
--import Graphics.UI.Gtk.Glade

import AgileKeychain
import Utils

mainWindow :: IO ()
mainWindow = do
  void initGUI
  window <- windowNew
  widgetShowAll window
  mainGUI
