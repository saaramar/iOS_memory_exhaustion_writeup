xcrun --sdk iphoneos clang -arch arm64 -framework IOKit exhaust_poc.c -O3 -o exhaust_poc
codesign -s - exhaust_poc --entitlement entitlements.xml  -f
