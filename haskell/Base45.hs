module Base45 (
    decodeBS
) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.List (elemIndex)

-- Base45 character set
charset :: String
charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

-- Reverse lookup for the character set
charsetMap :: Char -> Maybe Int
charsetMap c = elemIndex c charset

-- | Decodes a Base45 encoded ByteString.
decodeBS :: C8.ByteString -> Either String BS.ByteString
decodeBS bs = go (C8.unpack bs) []
  where
    go :: String -> [Int] -> Either String BS.ByteString
    go [] acc = Right $ BS.pack $ reverse $ map fromIntegral acc
    go (c1:c2:c3:rest) acc =
        case (charsetMap c1, charsetMap c2, charsetMap c3) of
            (Just v1, Just v2, Just v3) ->
                let val = v1 + v2 * 45 + v3 * 45 * 45
                in if val > 65535
                   then Left "Invalid Base45 sequence"
                   else let (h, l) = val `divMod` 256
                        in go rest (l:h:acc)
            _ -> Left "Invalid characters in Base45 string"
    go (c1:c2:rest) acc =
        case (charsetMap c1, charsetMap c2) of
            (Just v1, Just v2) ->
                let val = v1 + v2 * 45
                in if val > 255
                   then Left "Invalid Base45 sequence"
                   else go rest (val:acc)
            _ -> Left "Invalid characters in Base45 string"
    go [_] _ = Left "Invalid Base45 string length"
