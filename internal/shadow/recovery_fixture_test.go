package shadow

import contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"

func recoveryFixture() RecoveryRecord {
	deadline := contract.NewDeadline(1_000_000_000)
	return RecoveryRecord{
		Version: recoveryRecordVersion, Operation: "synthetic_execute", State: StatePlanned,
		AttemptID: "abcdefabcdefabcdefabcdefabcdefab", ChallengeID: "00112233445566778899aabbccddeeff",
		BuildSetDigest: testBuildDigest, SourceQualificationDigest: testSourceDigest,
		CleanupRoute: contract.CleanupRouteDirect, AccountBindingID: "aabbccddeeff0011", OptionsDigest: testOptionsDigest,
		RootLeaf: "attempt-abcdefabcdefabcdefabcdefabcdefab",
		BundleID: "com.zanescope.vlocal.shadow.abcdefabcdefabcdefabcdefabcdefab",
		Deadline: deadline, ExpectedSecurityPosture: "synthetic", PendingAction: ActionNone,
		Source:    SourceBinding{Leaf: "WeChat.app", Device: 1, Inode: 10, UID: 0, Mode: 0o755, ManifestDigest: testSourceDigest},
		Resources: []contract.ResourceBinding{},
	}
}
