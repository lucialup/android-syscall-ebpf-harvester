set -e


if ! adb devices | grep -q "device$"; then
    echo "Error: No Android device detected."
    exit 1
fi

echo "Running harvester for 10 seconds..."
echo ""

adb shell "cd /data/local/tmp/syscall-harvester && timeout 10 ./syscall_harvester > /data/local/tmp/test_output.log 2>&1 &"

sleep 2

echo "Generating test file operations..."
adb shell "cat /system/build.prop > /dev/null"
adb shell "ls /system/bin/ > /dev/null"
adb shell "cat /data/local/tmp/syscall-harvester/syscall_harvester > /dev/null"

sleep 9

echo ""
echo "======================================"
echo "Test Results:"
echo "======================================"
adb shell "cat /data/local/tmp/test_output.log | grep -E 'filename|Tracing|Filter' | head -20"
echo "Full logs available at: /data/local/tmp/test_output.log on device"
