package provider

import windowsroute "github.com/zanescope/v-local-key-provider/internal/platform/windows"

type windowsConfigMemoryReader = windowsroute.ConfigMemoryReader

func windowsConfigSensitiveRuntime() windowsroute.SensitiveRuntime {
	return windowsroute.SensitiveRuntime{
		CloneSensitive: cloneSensitiveBytes,
		MarkSensitive:  markSensitiveBytes,
		ClearSensitive: zeroBytes,
	}
}

func addWindowsConfigOffset(address uint64, offset int64) (uint64, bool) {
	return windowsroute.AddConfigOffset(address, offset)
}

func decodeWindowsConfigCipherCandidate(encoded []byte, recipe windowsConfigCipherRecipe) ([]byte, error) {
	return windowsroute.DecodeConfigCipherCandidate(encoded, recipe, windowsConfigSensitiveRuntime())
}

func extractWindowsConfigCipherCandidate(reader windowsConfigMemoryReader, needleAddress uint64, pointerSize int, recipe windowsConfigCipherRecipe) ([]byte, error) {
	return windowsroute.ExtractConfigCipherCandidate(reader, needleAddress, pointerSize, recipe, windowsConfigSensitiveRuntime())
}
