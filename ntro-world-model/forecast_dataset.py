"""Future-only examples with capture isolation and explicit gap handling."""
def make_examples(windows, history=16, horizon=8, stride=1, window_seconds=10):
    if min(history, horizon, stride, window_seconds) < 1:
        raise ValueError('history, horizon, stride and window_seconds must be positive')
    result = []
    for start in range(0, len(windows) - history - horizon + 1, stride):
        chunk = windows[start:start + history + horizon]
        if len({w.get('source_file') for w in chunk}) != 1:
            continue
        if any(b['time_window'] - a['time_window'] != window_seconds for a, b in zip(chunk, chunk[1:])):
            continue
        if any(w.get('ground_truth') not in (0, 1) for w in chunk):
            raise ValueError('Forecast training requires observed ground-truth annotations')
        past, future = chunk[:history], chunk[history:]
        result.append({
            'history': [w['state_vector'] for w in past],
            'future': [w['state_vector'] for w in future],
            'label': int(any(w['ground_truth'] for w in future)),
            'cutoff': past[-1]['time_window'],
            'target_start': future[0]['time_window'],
        })
    return result


def chronological_examples(windows, history=16, horizon=8):
    """Split raw windows FIRST; no observation/target can cross a split."""
    windows = sorted(windows, key=lambda w: (w['time_window'], w.get('source_file', '')))
    n = len(windows)
    a, b = int(n * .6), int(n * .8)
    splits = [make_examples(block, history, horizon) for block in
              (windows[:a], windows[a:b], windows[b:])]
    if any(not split for split in splits):
        raise ValueError('Insufficient contiguous labelled windows for a 60/20/20 forecast split')
    return splits
