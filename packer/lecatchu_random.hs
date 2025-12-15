{-# LANGUAGE RecordWildCards #-}

{-|
Module      : LeCatchu.Random
Description : Deterministic random number generation based on cryptographic hashing
Copyright   : (c) 2024
License     : MIT
Maintainer  : your.email@example.com

Provides a deterministic random number generator using the LeCatchu hash stream.
-}

module LeCatchu.Random
    ( LeRandom
    , newLeRandom
    , newLeRandomWithSeed
    , random
    , randomR
    , randomInt
    , randomIntR
    , randomBytes
    , shuffle
    , choice
    , choices
    ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word8)
import Data.IORef
import System.IO.Unsafe (unsafePerformIO)
import Data.Time.Clock.POSIX (getPOSIXTime)
import LeCatchu (LeCatchuEngine, hashStream, processHash)

-- | Deterministic random number generator state
data LeRandom = LeRandom
    { engine :: LeCatchuEngine
    , streamRef :: IORef [Integer]
    , xbase :: Int
    , interval :: Int
    , randBits :: Int
    }

-- | Create a new random generator with system time as seed
newLeRandom :: LeCatchuEngine -> Int -> Int -> IO LeRandom
newLeRandom eng xb iv = do
    time <- getPOSIXTime
    let seed = show time
    newLeRandomWithSeed eng seed xb iv

-- | Create a new random generator with specific seed
newLeRandomWithSeed :: LeCatchuEngine -> String -> Int -> Int -> IO LeRandom
newLeRandomWithSeed eng seed xb iv = do
    let stream = hashStream eng seed xb iv
    streamRef <- newIORef stream
    return $ LeRandom
        { engine = eng
        , streamRef = streamRef
        , xbase = xb
        , interval = iv
        , randBits = 16
        }

-- | Generate random double in [0, 1)
random :: LeRandom -> IO Double
random lr@LeRandom{..} = do
    stream <- readIORef streamRef
    let digits = take randBits stream
        digitStrs = map (\n -> show (n `mod` 10)) digits
        combined = concat digitStrs
        value = read ("0." ++ combined) :: Double
    writeIORef streamRef (drop randBits stream)
    return value

-- | Generate random double in range [a, b)
randomR :: LeRandom -> Double -> Double -> IO Double
randomR lr minVal maxVal = do
    r <- random lr
    return $ minVal + r * (maxVal - minVal)

-- | Generate random integer in [0, maxBound)
randomInt :: LeRandom -> IO Integer
randomInt lr = do
    stream <- readIORef streamRef
    let val = head stream
    writeIORef streamRef (tail stream)
    return val

-- | Generate random integer in range [a, b]
randomIntR :: LeRandom -> Integer -> Integer -> IO Integer
randomIntR lr minVal maxVal = do
    r <- random lr
    let range = maxVal - minVal + 1
    return $ minVal + floor (r * fromIntegral range)

-- | Generate random bytes
randomBytes :: LeRandom -> Int -> IO ByteString
randomBytes lr n = do
    stream <- readIORef streamRef
    let bytes = take n stream
        word8s = map (fromIntegral . (`mod` 256)) bytes :: [Word8]
    writeIORef streamRef (drop n stream)
    return $ BS.pack word8s

-- | Fisher-Yates shuffle
shuffle :: LeRandom -> [a] -> IO [a]
shuffle _ [] = return []
shuffle lr xs = go (length xs - 1) xs
  where
    go 0 ys = return ys
    go i ys = do
        j <- randomIntR lr 0 (fromIntegral i)
        let (before, y:after) = splitAt (fromIntegral j) ys
            ys' = before ++ after
            (before', target:after') = splitAt i ys'
        go (i - 1) (before' ++ y : after' ++ [target])

-- | Choose random element from list
choice :: LeRandom -> [a] -> IO (Maybe a)
choice _ [] = return Nothing
choice lr xs = do
    idx <- randomIntR lr 0 (fromIntegral $ length xs - 1)
    return $ Just $ xs !! fromIntegral idx

-- | Choose k random elements from list (with replacement)
choices :: LeRandom -> [a] -> Int -> IO [a]
choices lr xs k = sequence $ replicate k (fmap (maybe (head xs) id) (choice lr xs))

-- Example usage:
-- main :: IO ()
-- main = do
--     engine <- newEngine "Lehncrypt" 1 Packet False Nothing 1114112 3
--     rng <- newLeRandom engine 1 1
--     
--     -- Generate random numbers
--     r1 <- random rng
--     putStrLn $ "Random [0,1): " ++ show r1
--     
--     r2 <- randomR rng 10.0 20.0
--     putStrLn $ "Random [10,20): " ++ show r2
--     
--     i <- randomIntR rng 1 6  -- Dice roll
--     putStrLn $ "Dice roll: " ++ show i
--     
--     bytes <- randomBytes rng 16
--     putStrLn $ "Random bytes: " ++ show bytes
--     
--     let items = [1..10]
--     shuffled <- shuffle rng items
--     putStrLn $ "Shuffled: " ++ show shuffled
