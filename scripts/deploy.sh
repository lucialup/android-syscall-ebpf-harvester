set -e

if ! command -v adb &> /dev/null; then
    echo "Error: adb not found. Install Android SDK Platform-Tools."
    exit 1
fi

if ! adb devices | grep -q "device$"; then
    echo "Error: No Android device detected"
    exit 1
fi

echo "Building..."
make -C .. all

# Create directory on device
echo "Creating directory on device..."
adb shell "mkdir -p /data/local/tmp/syscall-harvester" 2>/dev/null || true

# Push files
echo "Pushing binaries..."
adb push ../build/syscall_harvester /data/local/tmp/syscall-harvester/
adb push ../build/syscall_harvester_kern.o /data/local/tmp/syscall-harvester/

# Set permissions
echo "Setting permissions..."
adb shell "chmod +x /data/local/tmp/syscall-harvester/syscall_harvester"

echo ""
echo "Deployment successful to /data/local/tmp/syscall-harvester on device!"
echo ""