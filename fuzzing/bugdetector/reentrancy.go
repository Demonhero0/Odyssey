package bugdetector

func detect_reentrancy(tracer *BugDetectorTracer) {
	// fmt.Println("Detecting reentrancy...")
	if len(tracer.callFrameStates) < 2 {
		return
	}

	lastCall := tracer.callFrameStates[len(tracer.callFrameStates)-1]

	if !lastCall.isContract {
		return
	}

	thisContract := lastCall.to

	if tracer.helperContract == thisContract {
		return
	}

	for _, call := range tracer.callFrameStates[:len(tracer.callFrameStates)-2] {
		if call.to == thisContract && len(call.tokenTransferList) > 0 {

			// for slot := range lastCall.pendingStorageWriteSet.successSet {
			// 	if _, exists := call.pendingStorageWriteSet.successSet[slot]; exists {
			// 	}
			// }
			// fmt.Println(index, call.to, len(tracer.callFrameStates), call.tokenTransferList)
		}
	}
}
