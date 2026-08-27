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

func extractWindowsConfigCipherCandidate(reader windowsConfigMemoryReader, needleAddress uint64, pointerSize int, recipe windowsConfigCipherRecipe) ([]byte, error) {
	return windowsroute.ExtractConfigCipherCandidate(reader, needleAddress, pointerSize, recipe, windowsConfigSensitiveRuntime())
}
