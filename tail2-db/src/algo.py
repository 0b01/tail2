# this is an algorithm for tiling precomputed/augmented time ranges
# ranges are decomposed into their constituent augmented ranges

avail = list(10 ** i for i in range(5))[::-1]
print(avail)

def r_u(v, s): return (v // s + 1) * s
def r_d(v, s): return (v // s) * s

def find(t0, t1):
    vals = []
    stack = [(t0, t1)]
    while stack:
        (t0, t1) = stack.pop()
        # print("start", t0, t1)
        if t0 == t1:
            continue
        for scale in avail:
            if t1 - t0 >= scale:
                n = (r_d(t1, scale) - t0) // scale
                # print(n)
                start = r_d(t0, scale)
                if start < t0:
                    start += scale
                if start + scale > t1:
                    continue
                end = start + scale * n
                vals += list((scale, i) for i in range(start, end, scale))
                if t1 != start:
                    stack.append((t0, start))
                if end != t0:
                    stack.append((end, t1))
                break
    return vals

def range_sub(rngs, to_sub):
    (t0, t1) = to_sub
    ret = []
    for (a, b) in rngs:
        if t0 >= a and t1 <= b:
            if a != t0:
                ret.append((a, t0))
            if t1 != b:
                ret.append((t1, b))
        else:
            ret.append((a, b))
    return ret

for i in range(1000):
    for j in range(i+1, 1000):
        t0 = i
        t1 = j
        # print(t0, t1)

        plan = find(t0, t1)
        orig = [(t0, t1)]
        for (interval, start) in plan:
            r = (start, start + interval)
            orig = range_sub(orig, r)
        assert(orig == [])
    # break