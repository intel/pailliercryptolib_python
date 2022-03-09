import numpy as np

# from ipcl_python import PaillierKeypair
import time
import google_benchmark as benchmark
from google_benchmark import Counter


@benchmark.register
def empty(state):
    while state:
        pass


@benchmark.register
def sum_million(state):
    while state:
        sum(range(1_000_000))


@benchmark.register
def pause_timing(state):
    """Pause timing every iteration."""
    while state:
        # Construct a list of random ints every iteration without timing it
        state.pause_timing()
        random_list = [np.random.randint(0, 100) for _ in range(100)]
        state.resume_timing()
        # Time the in place sorting algorithm
        random_list.sort()


@benchmark.register
def skipped(state):
    if True:  # Test some predicate here.
        state.skip_with_error("some error")
        return  # NOTE: You must explicitly return, or benchmark will continue.

    ...  # Benchmark code would be here.


@benchmark.register
def manual_timing(state):
    while state:
        # Manually count Python CPU time
        start = time.perf_counter()  # perf_counter_ns() in Python 3.7+
        # Something to benchmark
        time.sleep(0.01)
        end = time.perf_counter()
        state.set_iteration_time(end - start)


@benchmark.register
def custom_counters(state):
    """Collect custom metric using benchmark.Counter."""
    num_foo = 0.0
    while state:
        # Benchmark some code here
        pass
        # Collect some custom metric named foo
        num_foo += 0.13

    # Automatic Counter from numbers.
    state.counters["foo"] = num_foo
    # Set a counter as a rate.
    state.counters["foo_rate"] = Counter(num_foo, Counter.kIsRate)
    #  Set a counter as an inverse of rate.
    state.counters["foo_inv_rate"] = Counter(
        num_foo, Counter.kIsRate | Counter.kInvert
    )
    # Set a counter as a thread-average quantity.
    state.counters["foo_avg"] = Counter(num_foo, Counter.kAvgThreads)
    # There's also a combined flag:
    state.counters["foo_avg_rate"] = Counter(num_foo, Counter.kAvgThreadsRate)


@benchmark.register
@benchmark.option.measure_process_cpu_time()
@benchmark.option.use_real_time()
def with_options(state):
    while state:
        sum(range(1_000_000))


@benchmark.register(name="sum_million_microseconds")
@benchmark.option.unit(benchmark.kMicrosecond)
def with_options2(state):
    while state:
        sum(range(1_000_000))


@benchmark.register
@benchmark.option.arg(100)
@benchmark.option.arg(1000)
def passing_argument(state):
    while state:
        sum(range(state.range(0)))


@benchmark.register
@benchmark.option.range(8, limit=8 << 10)
def using_range(state):
    while state:
        sum(range(state.range(0)))


@benchmark.register
@benchmark.option.range_multiplier(2)
@benchmark.option.range(1 << 10, 1 << 18)
@benchmark.option.complexity(benchmark.oN)
def computing_complexity(state):
    while state:
        sum(range(state.range(0)))
    state.complexity_n = state.range(0)


if __name__ == "__main__":
    benchmark.main()
