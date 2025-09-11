package fuzzing

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

type MetricPoint struct {
	// Time represents time elapsed since the start of the fuzzing.
	Time float64 `json:"time"`
	// NumSequences represents the number of call sequences executed.
	NumSequences *big.Int `json:"num_sequences"`

	// NumCalls represents the number of calls executed
	NumCalls *big.Int `json:"num_calls"`
	// CorpusSize represents the number of mutable call sequences in the corpus.
	CorpusSize int `json:"corpus_size"`
	// NumReports represents the number of reports generated.
	NumReports int `json:"num_reports"`

	Coverage       *float64 `json:"coverage,omitempty"`
	BlockCoverage  *float64 `json:"block_coverage,omitempty"`
	BranchCoverage *float64 `json:"branch_coverage,omitempty"`

	Dataflow     *int `json:"dataflow,omitempty"`
	StorageWrite *int `json:"storage_write,omitempty"`

	InstructionNumber *int                         `json:"instructionNumber,omitempty"`
	BranchNumber      *int                         `json:"branchNumber,omitempty"`
	VariableValueMap  map[string]map[string]uint64 `json:"variableValueMap,omitempty"`
	DirectionMap      map[string]uint64            `json:"directionMap,omitempty"`

	// bug detection
	Bugs []string `json:"bugs"`
}

var timeLogMetricPoints []MetricPoint

// logMetricsTimeLoop logs fuzzing metrics to file at specified interval until
// ctx signals a stopped operation.
func (f *Fuzzer) logMetricsTimeLoop() {
	timeInterval := time.Duration(f.config.Fuzzing.MetricLogConfig.TimeInterval) * time.Second
	if timeInterval == 0 {
		return
	}

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-time.After(timeInterval):
			err := f.logMetrics(&timeLogMetricPoints, f.config.Fuzzing.MetricLogConfig.TimeLogFile)
			if err != nil {
				f.logger.Warn(err)
			}
		}
	}
}

var sequenceLogMetricPoints []MetricPoint
var sequenceLogLock sync.Mutex

func (f *Fuzzer) logMetricsSequenceTestedSubscriber() {
	sequenceInterval := int64(f.config.Fuzzing.MetricLogConfig.SequenceInterval)
	if sequenceInterval == 0 {
		return
	}

	// Add 1 to the number of sequences tested, as the event is published before the number increases.
	numSequenceTested := new(big.Int).Add(f.metrics.SequencesTested(), big.NewInt(1))

	if new(big.Int).Mod(numSequenceTested, big.NewInt(sequenceInterval)).Cmp(big.NewInt(0)) == 0 {
		sequenceLogLock.Lock()
		err := f.logMetrics(&sequenceLogMetricPoints, f.config.Fuzzing.MetricLogConfig.SequenceLogFile)
		sequenceLogLock.Unlock()
		if err != nil {
			f.logger.Warn(err)
		}
	}
}

func (f *Fuzzer) logMetrics(metricPoints *[]MetricPoint, filePath string) error {
	mp := MetricPoint{
		Time:         time.Since(f.startTime).Seconds(),
		NumSequences: f.metrics.SequencesTested(),
		NumCalls:     f.metrics.CallsTested(),
		CorpusSize:   f.corpus.CallSequenceEntryCount(true, false, false),
		NumReports:   f.corpus.CallSequenceEntryCount(false, false, true),
	}
	if f.config.Fuzzing.UseCoverageTracing() {
		c, t := f.corpus.CoverageMaps().TotalCodeCoverage(true, f.targetContractAddresses)
		rate := float64(c) / float64(t)
		mp.Coverage = &rate
		mp.InstructionNumber = &c
	}
	if f.config.Fuzzing.UseBranchCoverageTracing() {
		c, t := f.corpus.BranchCoverageMaps().TotalBranchCoverage(true, f.targetContractAddresses)
		rate := float64(c) / float64(t)
		mp.BranchCoverage = &rate
		mp.BranchNumber = &c
	}
	if f.config.Fuzzing.UseStorageWriteTracing() {
		count := f.corpus.StorageWriteSet().TotalStorageWriteCount(true)
		mp.StorageWrite = &count
	}
	if f.config.Fuzzing.MetricRecordConfig.StateEnabled {
		mp.VariableValueMap = f.corpus.InvariantMaps().VariableValueMap()
		mp.DirectionMap = f.corpus.InvariantMaps().DirectionMap()
	}

	if f.config.Fuzzing.UseBugDetector() {
		mp.Bugs = f.corpus.BugMap().BugDetectionResult()
	}
	*metricPoints = append(*metricPoints, mp)

	jsonData, err := json.Marshal(*metricPoints)
	if err != nil {
		return fmt.Errorf("failed to marshal metric points to JSON, err: %v", err)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create metric log file %s, err: %v", filePath, err)
	}
	defer file.Close()

	_, err = file.Write(jsonData)
	if err != nil {
		return fmt.Errorf("failed to write metric points to file %s, err: %v", filePath, err)
	}

	return nil
}
