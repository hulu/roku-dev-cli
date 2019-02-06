import pytest

from roku_dev_cli import RendezvousReporter

def test_parsing():
    reporter = RendezvousReporter()

    blockLine = "02-01 21:44:41.464 [sg.node.BLOCK  ] Rendezvous[2082] at pkg:/components/SomeTask.brs(178)"
    unblockLine = "02-01 21:44:41.483 [sg.node.UNBLOCK] Rendezvous[2082] completed in 0.002 s"
    
    # ignore unrelated lines
    assert reporter.parseLine("some random line") == None

    # can parse rendezvous index from string
    assert reporter.parseRendezvousIndex(blockLine) == '2082'
    assert reporter.parseRendezvousIndex(unblockLine) == '2082'

    # can parse file path
    assert reporter.parseFilePath(blockLine) == "pkg:/components/SomeTask.brs"
    assert reporter.parseFilePath("roku_analytics:/components/AnalyticsUtils.brs(221)") == "roku_analytics:/components/AnalyticsUtils.brs"
    with pytest.raises(ValueError):
        reporter.parseFilePath(unblockLine)

    # can parse file number
    assert reporter.parseLineNumber(blockLine) == '178'
    with pytest.raises(ValueError):
        reporter.parseLineNumber(unblockLine)

    # can parse a duration
    with pytest.raises(ValueError):
        reporter.parseRendezvousDuration(blockLine)
    assert reporter.parseRendezvousDuration(unblockLine) == '0.002'
    unblockedNoCompletion = "02-04 18:23:11.026 [sg.node.UNBLOCK] Rendezvous[4927] completed"
    assert reporter.parseRendezvousDuration(unblockedNoCompletion) == "0.000"

def test_reporting():
    reporter = RendezvousReporter()

    lineNumbers = [2,3,5,6]
    assert reporter.hyphenateRanges(lineNumbers, 1) == ["2-3", "5-6"]

    lineNumbers = [2,3,6,7,8]
    assert reporter.hyphenateRanges(lineNumbers, 2) == ["2-3", "6-8"]
