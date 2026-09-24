#!/bin/bash
# Build the no-adb app-chain APK (option #2). Reuses the primary chain's prebuilt aarch64 binaries
# (fuguquest, dfpoison) + e2e.dex + targets — read-only, the primary chain is not modified.
#   aapt2 link -> javac -> d8 -> (add classes.dex + libs) -> zipalign -> apksigner
set -euo pipefail
SDK=${SDK:-/home/henry/Tools/android-sdk}
BT=${BT:-$SDK/build-tools/34.0.0}
PLATFORM=${PLATFORM:-$SDK/platforms/android-33/android.jar}
JDK=${JDK:-/home/henry/Tools/jdk-21}
export JAVA_HOME="$JDK"; export PATH="$JDK/bin:$PATH"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"          # poc/dirtyfrag-lpe
OUT="$HERE/build"; APK="$HERE/fuguapp.apk"; KS="$OUT/debug.keystore"

FUGU="$ROOT/rust/target/aarch64-linux-android/release/fuguquest"
DFP="$ROOT/agent/target/aarch64-linux-android/release/dfpoison"
[ -f "$FUGU" ] || { echo "building fuguquest (aarch64)..."; (cd "$ROOT/rust" && cargo build --release --target aarch64-linux-android >/dev/null); }
[ -f "$DFP" ]  || { echo "building dfpoison (aarch64)...";  (cd "$ROOT/agent" && cargo build --release --target aarch64-linux-android >/dev/null); }

rm -rf "$OUT"; mkdir -p "$OUT/classes" "$OUT/gen" "$OUT/stage/lib/arm64-v8a" "$OUT/stage/assets/fugu/targets"
# bundle native binaries as extractable libs (executable from nativeLibraryDir)
cp "$FUGU" "$OUT/stage/lib/arm64-v8a/libfugu.so"
cp "$DFP"  "$OUT/stage/lib/arm64-v8a/libdfpoison.so"
# bundle e2e.dex + targets (data files fuguquest/dfpoison read on device)
cp "$ROOT/e2e.dex" "$OUT/stage/assets/fugu/e2e.dex"
cp -r "$ROOT/targets/." "$OUT/stage/assets/fugu/targets/"

echo "[1/5] aapt2 link (with assets)"
"$BT/aapt2" link -I "$PLATFORM" --manifest "$HERE/AndroidManifest.xml" --java "$OUT/gen" \
  -A "$OUT/stage/assets" --min-sdk-version 29 --target-sdk-version 33 -o "$OUT/base.apk"

echo "[2/5] javac"
find "$HERE/src" "$OUT/gen" -name '*.java' > "$OUT/sources.txt"
"$JDK/bin/javac" -source 8 -target 8 -bootclasspath "$PLATFORM" -classpath "$PLATFORM" -d "$OUT/classes" -nowarn @"$OUT/sources.txt"

echo "[3/5] d8"
find "$OUT/classes" -name '*.class' > "$OUT/classes.txt"
"$BT/d8" --min-api 29 --lib "$PLATFORM" --output "$OUT" @"$OUT/classes.txt"

echo "[4/5] assemble apk (classes.dex + native libs)"
cp "$OUT/base.apk" "$OUT/app.apk"
( cd "$OUT" && zip -q -u app.apk classes.dex )
( cd "$OUT/stage" && zip -q -r "$OUT/app.apk" lib )

echo "[5/5] zipalign + sign"
"$BT/zipalign" -f -p 4 "$OUT/app.apk" "$OUT/aligned.apk"
[ -f "$KS" ] || "$JDK/bin/keytool" -genkeypair -noprompt -keystore "$KS" -storepass android -keypass android \
  -alias poc -keyalg RSA -keysize 2048 -validity 3650 -dname "CN=fuguapp, OU=research, O=research, C=US"
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
  --v1-signing-enabled true --v2-signing-enabled true --out "$APK" "$OUT/aligned.apk"
echo "built: $APK"
