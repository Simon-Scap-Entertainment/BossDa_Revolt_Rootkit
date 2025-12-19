@echo off
ghc -O2 -Wall -o pe_loader.exe Main.hs EncodedPayload.hs Base45.hs -lkernel32 -luser32
