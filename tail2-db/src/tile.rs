#[allow(unused)]
fn r_u(v: i64, s: i64) -> i64 {
    (v / s + 1) * s
}

fn r_d(v: i64, s: i64) -> i64 {
    (v / s) * s
}

/// tile a range(inclusive) with available timescales
pub fn tile((t0, t1): (i64, i64), available_timescales: &[i64]) -> Vec<(i64, i64)> {
    let mut vals = Vec::new();
    let mut stack = vec![(t0, t1)];
    while !stack.is_empty() {
        let (t0, t1) = stack.pop().unwrap();
        if t0 == t1 {
            continue;
        }
        for scale in available_timescales {
            let scale = *scale;
            if t1 - t0 >= scale {
                let n = (r_d(t1, scale) - t0) / scale;
                let mut start = r_d(t0, scale);
                if start < t0 {
                    start += scale;
                }
                if start + scale > t1 {
                    continue;
                }
                let end = start + scale * n;
                for i in (start..end).step_by(scale as _) {
                    vals.push((scale, i));
                }
                if t1 != start {
                    stack.push((t0, start));
                }
                if end != t0 {
                    stack.push((end, t1));
                }
                break;
            }
        }
    }
    vals
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range_sub(rngs: &[(i64, i64)], to_sub: (i64, i64)) -> Vec<(i64, i64)> {
        let (t0, t1) = to_sub;
        let mut ret = Vec::new();
        for (a, b) in rngs {
            if t0 >= *a && t1 <= *b {
                if a != &t0 {
                    ret.push((*a, t0));
                }
                if t1 != *b {
                    ret.push((t1, *b));
                }
            } else {
                ret.push((*a, *b));
            }
        }
        ret
    }

    #[test]
    fn test_tile_full() {
        let avail: Vec<_> = (0..6).rev().map(|i| 10_i64.pow(i)).collect();

        for i in 0..1000 {
            for j in i + 1..1000 {
                let t0 = i;
                let t1 = j;

                let plan = tile((t0, t1), &avail);
                let mut orig = vec![(t0, t1)];
                for (interval, start) in plan {
                    let r = (start, start + interval);
                    orig = range_sub(&orig, r);
                }
                assert_eq!(orig, vec![]);
            }
        }
    }

    #[test]
    fn test_tile() {
        let avail: Vec<_> = (0..6).rev().map(|i| 10_i64.pow(i)).collect();

        let ret = tile((0, 20000), avail.as_slice());
        assert_eq!(ret, vec![(10000, 0), (10000, 10000)]);

        let ret = tile((0, 10000), avail.as_slice());
        assert_eq!(ret, vec![(10000, 0)]);

        let ret = tile((0, 9999), avail.as_slice());
        let exp = vec![
            (1000, 0),
            (1000, 1000),
            (1000, 2000),
            (1000, 3000),
            (1000, 4000),
            (1000, 5000),
            (1000, 6000),
            (1000, 7000),
            (1000, 8000),
            (100, 9000),
            (100, 9100),
            (100, 9200),
            (100, 9300),
            (100, 9400),
            (100, 9500),
            (100, 9600),
            (100, 9700),
            (100, 9800),
            (10, 9900),
            (10, 9910),
            (10, 9920),
            (10, 9930),
            (10, 9940),
            (10, 9950),
            (10, 9960),
            (10, 9970),
            (10, 9980),
            (1, 9990),
            (1, 9991),
            (1, 9992),
            (1, 9993),
            (1, 9994),
            (1, 9995),
            (1, 9996),
            (1, 9997),
            (1, 9998),
        ];
        assert_eq!(ret, exp);
    }
}
