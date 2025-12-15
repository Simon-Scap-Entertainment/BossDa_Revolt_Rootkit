{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE BangPatterns #-}

module LeCatchu
    ( LeCatchuEngine(..)
    , EncodingType(..)
    , newEngine
    , encode
    , decode
    , cachedHash
    , processHash
    , hashStream
    , encrypt
    , decrypt
    , encryptWithIV
    , decryptWithIV
    , addIV
    , delIV
    ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as C8
import Data.ByteString (ByteString)
import Data.Word (Word8)
import Data.Bits ((.&.))
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Crypto.Hash (hash, Digest, Blake2b_256)
import qualified Crypto.Hash as H
import Data.ByteArray (convert)
import Data.ByteArray.Encoding (convertToBase, Base(Base16))
import System.Random (StdGen, mkStdGen, randomR)
import Data.List (unfoldr)
import Control.Monad.State
import System.IO.Unsafe (unsafePerformIO)
import System.Entropy (getEntropy)

-- | Encoding types supported
data EncodingType = Packet | Separator
    deriving (Show, Eq)

-- | Main engine structure
data LeCatchuEngine = LeCatchuEngine
    { sbox :: Map Char ByteString
    , resbox :: Map ByteString Char
    , encodingType :: EncodingType
    , perlength :: Int
    , specialExchange :: Maybe String
    , unicodeSupport :: Int
    , shuffleSbox :: Bool
    , sboxSeed :: String
    , sboxSeedXBase :: Int
    } deriving (Show)

-- | Create a new LeCatchu engine
newEngine :: String           -- ^ S-box seed
          -> Int              -- ^ S-box seed xbase
          -> EncodingType     -- ^ Encoding type
          -> Bool             -- ^ Shuffle s-box
          -> Maybe String     -- ^ Special exchange string
          -> Int              -- ^ Unicode support (max codepoint)
          -> Int              -- ^ Per-length for encoding
          -> LeCatchuEngine
newEngine seed xbase encType shuffle specEx uniSup perLen =
    let hashVal = processHashInternal seed xbase specEx
        gen = mkStdGen (fromIntegral $ hashVal `mod` (2^31 - 1))
        
        mxn = if encType == Packet then 256 else 255
        
        -- Generate all byte combinations
        combos = if encType == Separator
                 then concatMap (\len -> generateCombos mxn len) [1..perLen]
                 else generateCombos mxn perLen
        
        -- Shuffle if needed
        finalCombos = if shuffle
                      then shuffleList gen combos
                      else combos
        
        -- Take only what we need for unicode support
        usedCombos = take uniSup finalCombos
        
        -- Build the mappings
        (sboxMap, resboxMap) = buildMaps usedCombos 0
        
    in LeCatchuEngine
        { sbox = sboxMap
        , resbox = resboxMap
        , encodingType = encType
        , perlength = perLen
        , specialExchange = specEx
        , unicodeSupport = uniSup
        , shuffleSbox = shuffle
        , sboxSeed = seed
        , sboxSeedXBase = xbase
        }

-- | Generate all byte combinations of given length
generateCombos :: Int -> Int -> [ByteString]
generateCombos maxVal len = map BS.pack $ sequence $ replicate len [0..fromIntegral (maxVal-1)]

-- | Shuffle a list using a random generator
shuffleList :: StdGen -> [a] -> [a]
shuffleList gen xs = evalState (shuffle' xs) gen
  where
    shuffle' [] = return []
    shuffle' [x] = return [x]
    shuffle' lst = do
        let len = length lst
        idx <- state $ randomR (0, len - 1)
        let (before, x:after) = splitAt idx lst
        rest <- shuffle' (before ++ after)
        return (x : rest)

-- | Build s-box and reverse s-box maps
buildMaps :: [ByteString] -> Int -> (Map Char ByteString, Map ByteString Char)
buildMaps combos start = go combos start Map.empty Map.empty
  where
    go [] _ sMap rMap = (sMap, rMap)
    go (c:cs) n sMap rMap =
        let ch = toEnum n :: Char
            sMap' = Map.insert ch c sMap
            rMap' = Map.insert c ch rMap
        in go cs (n+1) sMap' rMap'

-- | Encode a string to bytes
encode :: LeCatchuEngine -> String -> ByteString
encode engine str = case encodingType engine of
    Packet -> BS.concat [Map.findWithDefault BS.empty c (sbox engine) | c <- str]
    Separator -> BS.intercalate (BS.singleton 255) [Map.findWithDefault BS.empty c (sbox engine) | c <- str]

-- | Decode bytes to string
decode :: LeCatchuEngine -> ByteString -> String
decode engine bytes = case encodingType engine of
    Packet -> 
        let len = perlength engine
            chunks = chunkByteString len bytes
        in [Map.findWithDefault '?' chunk (resbox engine) | chunk <- chunks]
    Separator ->
        let parts = BS.split 255 bytes
        in [Map.findWithDefault '?' part (resbox engine) | part <- parts]

-- | Chunk a ByteString into fixed-size pieces
chunkByteString :: Int -> ByteString -> [ByteString]
chunkByteString n bs
    | BS.null bs = []
    | otherwise = let (chunk, rest) = BS.splitAt n bs
                  in chunk : chunkByteString n rest

-- | Cached hash function using BLAKE2b
cachedHash :: Maybe String -> String -> String
cachedHash specEx input =
    let input' = case specEx of
                   Just ex -> input ++ ex
                   Nothing -> input
        digest = hash (C8.pack input') :: Digest Blake2b_256
    in C8.unpack $ convertToBase Base16 (convert digest :: ByteString)

-- | Internal process hash (no cache lookup simulation)
processHashInternal :: String -> Int -> Maybe String -> Integer
processHashInternal key xbase specEx =
    let go k origKey 0 acc = acc
        go k origKey n acc =
            let h = cachedHash specEx (k ++ origKey)
                combined = acc ++ h
            in go h origKey (n-1) combined
        hashes = go key key xbase ""
    in read ("0x" ++ hashes) :: Integer

-- | Process hash - converts key to large integer
processHash :: LeCatchuEngine -> String -> Int -> Integer
processHash engine key xbase = processHashInternal key xbase (specialExchange engine)

-- | Generate infinite hash stream
hashStream :: LeCatchuEngine -> String -> Int -> Int -> [Integer]
hashStream engine key xbase interval =
    let origKey = key
        generate k tKey counter =
            if counter `mod` interval == 0
                then let tKey' = k
                         result = processHashInternal (k ++ origKey ++ tKey') xbase (specialExchange engine)
                         k' = cachedHash (specialExchange engine) (k ++ origKey ++ tKey')
                     in result : generate k' tKey' (counter + 1)
                else let k' = cachedHash (specialExchange engine) (k ++ origKey ++ tKey)
                     in generate k' tKey (counter + 1)
    in generate key key 0

-- | Encrypt bytes with key
encrypt :: LeCatchuEngine -> ByteString -> String -> Int -> Int -> ByteString
encrypt engine bytes key xbase interval =
    let stream = hashStream engine key xbase interval
        encryptByte (b, k) = fromIntegral ((fromIntegral b + k) `mod` 256) :: Word8
    in BS.pack $ zipWith (\b k -> fromIntegral ((fromIntegral b + k) `mod` 256)) (BS.unpack bytes) stream

-- | Decrypt bytes with key
decrypt :: LeCatchuEngine -> ByteString -> String -> Int -> Int -> ByteString
decrypt engine bytes key xbase interval =
    let stream = hashStream engine key xbase interval
    in BS.pack $ zipWith (\b k -> fromIntegral ((fromIntegral b - k) `mod` 256)) (BS.unpack bytes) stream

-- | Add initialization vector to data
addIV :: LeCatchuEngine -> ByteString -> Int -> Int -> Int -> IO ByteString
addIV engine dataBytes ivLength ivXBase ivInterval = do
    ivKey <- getEntropy ivLength
    let encrypted = encrypt engine dataBytes (show $ BS.unpack ivKey) ivXBase ivInterval
    return $ BS.append ivKey encrypted

-- | Remove initialization vector from data
delIV :: LeCatchuEngine -> ByteString -> Int -> Int -> Int -> ByteString
delIV engine dataBytes ivLength ivXBase ivInterval =
    let (ivKey, encrypted) = BS.splitAt ivLength dataBytes
        decrypted = decrypt engine encrypted (show $ BS.unpack ivKey) ivXBase ivInterval
    in decrypted

-- | Encrypt with IV (recommended)
encryptWithIV :: LeCatchuEngine -> ByteString -> String -> Int -> Int -> Int -> Int -> Int -> IO ByteString
encryptWithIV engine dataBytes key xbase interval ivLength ivXBase ivInterval = do
    withIV <- addIV engine dataBytes ivLength ivXBase ivInterval
    return $ encrypt engine withIV key xbase interval

-- | Decrypt with IV (recommended)
decryptWithIV :: LeCatchuEngine -> ByteString -> String -> Int -> Int -> Int -> Int -> Int -> ByteString
decryptWithIV engine dataBytes key xbase interval ivLength ivXBase ivInterval =
    let decrypted = decrypt engine dataBytes key xbase interval
    in delIV engine decrypted ivLength ivXBase ivInterval

{-----------------------------------------------------------------------
 LeCatchu.Extra - Additional cryptographic functions
 
 Provides advanced encryption modes:
 - Chain mode (CBC-like)
 - SlowDE (Slow Decryption)
 - Raw encryption (ECB-like)
 - Armor encryption (authenticated)
-----------------------------------------------------------------------}

-- | Chain encryption (similar to CBC)
encryptChain :: LeCatchuEngine -> ByteString -> String -> Int -> Int -> Int -> Int -> ByteString
encryptChain engine mainData key xbase chainXBase interval blockSize =
    let keygen = hashStream engine key xbase interval
        blocks = chunkByteString blockSize mainData
        
        processBlock :: [Integer] -> ByteString -> (ByteString, [Integer])
        processBlock stream block =
            let chainStream = chainBackStream engine block chainXBase
                encrypted = BS.pack $ zipWith3 (\b k c -> fromIntegral ((fromIntegral b + k + c) `mod` 256))
                                              (BS.unpack block) stream chainStream
                stream' = drop (BS.length block) stream
            in (encrypted, stream')
        
        go :: [Integer] -> [ByteString] -> ByteString
        go _ [] = BS.empty
        go stream (blk:blks) =
            let (enc, stream') = processBlock stream blk
            in BS.append enc (go stream' blks)
            
    in go keygen blocks

-- | Decrypt chain
decryptChain :: LeCatchuEngine -> ByteString -> String -> Int -> Int -> Int -> Int -> ByteString
decryptChain engine mainData key xbase chainXBase interval blockSize =
    let keygen = hashStream engine key xbase interval
        blocks = chunkByteString blockSize mainData
        
        processBlock :: [Integer] -> ByteString -> (ByteString, [Integer])
        processBlock stream block =
            let decrypted = decryptChainBlock stream block 0 []
                stream' = drop (BS.length block) stream
            in (BS.pack decrypted, stream')
        
        decryptChainBlock stream block lastChain acc
            | BS.null block = reverse acc
            | otherwise =
                let b = BS.head block
                    k = head stream
                    decrypted = fromIntegral ((fromIntegral b - k - lastChain) `mod` 256) :: Word8
                    newChain = processHashInternal (show (acc ++ [decrypted])) chainXBase (specialExchange engine) `mod` 256
                in decryptChainBlock (tail stream) (BS.tail block) (fromIntegral newChain) (acc ++ [decrypted])
        
        go :: [Integer] -> [ByteString] -> ByteString
        go _ [] = BS.empty
        go stream (blk:blks) =
            let (dec, stream') = processBlock stream blk
            in BS.append dec (go stream' blks)
            
    in go keygen blocks

-- | Chain back stream for CBC-like behavior
chainBackStream :: LeCatchuEngine -> ByteString -> Int -> [Integer]
chainBackStream engine block chainXBase =
    0 : [processHashInternal (show $ BS.unpack $ BS.take (i+1) block) chainXBase (specialExchange engine) `mod` 256 
         | i <- [0..BS.length block - 1]]

-- | Raw encryption (ECB-like single block)
encryptRaw :: LeCatchuEngine -> ByteString -> String -> Int -> ByteString
encryptRaw engine dataBytes key xbase =
    let keyHash = processHashInternal key xbase (specialExchange engine)
    in BS.pack [fromIntegral ((fromIntegral b + keyHash) `mod` 256) | b <- BS.unpack dataBytes]

-- | Raw decryption
decryptRaw :: LeCatchuEngine -> ByteString -> String -> Int -> ByteString
decryptRaw engine dataBytes key xbase =
    let keyHash = processHashInternal key xbase (specialExchange engine)
    in BS.pack [fromIntegral ((fromIntegral b - keyHash) `mod` 256) | b <- BS.unpack dataBytes]

-- Example usage and testing:
-- main :: IO ()
-- main = do
--     let engine = newEngine "Lehncrypt" 1 Packet False Nothing 1114112 3
--     
--     -- Encode/decode example
--     let text = "Hello, World!"
--     let encoded = encode engine text
--     let decoded = decode engine encoded
--     putStrLn $ "Original: " ++ text
--     putStrLn $ "Decoded: " ++ decoded
--     
--     -- Encryption example
--     let plaintext = C8.pack "Secret message"
--     encrypted <- encryptWithIV engine plaintext "mykey" 1 1 256 1 1
--     let decrypted = decryptWithIV engine encrypted "mykey" 1 1 256 1 1
--     putStrLn $ "Decrypted: " ++ C8.unpack decrypted
--     
--     -- Chain encryption
--     let chainEnc = encryptChain engine plaintext "mykey" 1 1 1 512
--     let chainDec = decryptChain engine chainEnc "mykey" 1 1 1 512
--     putStrLn $ "Chain decrypted: " ++ C8.unpack chainDec
