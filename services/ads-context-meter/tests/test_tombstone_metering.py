from ads_commons.context_compactor import active_context, memory_text, recall_source
from ads_commons.context_meter import MeterRequest
from ads_commons.engine import UserHistoryTurn
from ads_context_meter.counter import counting_messages
from context_fakes import memory


def test_meter_counts_only_visible_memory_and_explicit_remainder_once():
    inner = memory([UserHistoryTurn("old archive")], [UserHistoryTurn("stale remainder")])
    outer = memory([UserHistoryTurn("new archive")], [UserHistoryTurn("current")], inner)
    visible = counting_messages(MeterRequest("glm-5.3", active_context(outer)))
    assert visible == [
        {"role": "user", "content": memory_text(outer)},
        {"role": "user", "content": "current"},
    ]
    source = counting_messages(MeterRequest("glm-5.3", recall_source(outer)))
    assert source == [
        {"role": "user", "content": memory_text(inner)},
        {"role": "user", "content": "new archive"},
    ]
    assert "stale remainder" not in str(source) and "old archive" not in str(source)
