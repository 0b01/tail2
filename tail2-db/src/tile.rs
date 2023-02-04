//! Algorithm for tiling

/// Represent a tile with the time scale and the start time
#[derive(Debug, PartialEq, Eq)]
pub struct Tile {
    /// Time scale
    pub scale: i64,
    /// Start time
    pub start: i64,
}

/// round down to the nearest multiple of s
fn round_down(v: i64, s: i64) -> i64 {
    (v / s) * s
}

/// tile a range(inclusive) with available timescales
pub fn tile((t0, t1): (i64, i64), available_timescales: &[i64]) -> Vec<Tile> {
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
                let n = (round_down(t1, scale) - t0) / scale;
                let mut start = round_down(t0, scale);
                if start < t0 {
                    start += scale;
                }
                if start + scale > t1 {
                    continue;
                }
                let end = start + scale * n;
                for i in (start..end).step_by(scale as _) {
                    vals.push(Tile{scale, start: i});
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
                for Tile {scale, start} in plan {
                    let r = (start, start + scale);
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
        assert_eq!(ret, vec![Tile{scale:10000, start: 0}, Tile {scale: 10000, start: 10000}]);

        let ret = tile((0, 10000), avail.as_slice());
        assert_eq!(ret, vec![Tile{ scale: 10000, start: 0 }]);

        let ret = tile((0, 9999), avail.as_slice());
        let exp = vec![
            Tile{scale: 1000, start: 0},
            Tile{scale: 1000, start: 1000},
            Tile{scale: 1000, start: 2000},
            Tile{scale: 1000, start: 3000},
            Tile{scale: 1000, start: 4000},
            Tile{scale: 1000, start: 5000},
            Tile{scale: 1000, start: 6000},
            Tile{scale: 1000, start: 7000},
            Tile{scale: 1000, start: 8000},
            Tile{scale: 100, start: 9000},
            Tile{scale: 100, start: 9100},
            Tile{scale: 100, start: 9200},
            Tile{scale: 100, start: 9300},
            Tile{scale: 100, start: 9400},
            Tile{scale: 100, start: 9500},
            Tile{scale: 100, start: 9600},
            Tile{scale: 100, start: 9700},
            Tile{scale: 100, start: 9800},
            Tile{scale: 10, start: 9900},
            Tile{scale: 10, start: 9910},
            Tile{scale: 10, start: 9920},
            Tile{scale: 10, start: 9930},
            Tile{scale: 10, start: 9940},
            Tile{scale: 10, start: 9950},
            Tile{scale: 10, start: 9960},
            Tile{scale: 10, start: 9970},
            Tile{scale: 10, start: 9980},
            Tile{scale: 1, start: 9990},
            Tile{scale: 1, start: 9991},
            Tile{scale: 1, start: 9992},
            Tile{scale: 1, start: 9993},
            Tile{scale: 1, start: 9994},
            Tile{scale: 1, start: 9995},
            Tile{scale: 1, start: 9996},
            Tile{scale: 1, start: 9997},
            Tile{scale: 1, start: 9998},
        ];
        assert_eq!(ret, exp);
    }
}
