(define-map big-map {
  a: uint,
  b: uint,
  c: uint
} {
  a: uint,
  b: uint,
  c: uint,
})

(define-public (set-data (a uint) (b uint) (c uint))
  (begin
    (map-get? big-map { a: a, b: b, c: c })
    (map-set big-map { a: a, b: b, c: c } { a: a, b: b, c: c })
    (map-get? big-map { a: a, b: b, c: c })
    (map-set big-map { a: a, b: b, c: c } { a: a, b: b, c: c })
    (map-get? big-map { a: a, b: b, c: c })
    (map-set big-map { a: a, b: b, c: c } { a: a, b: b, c: c })
    (map-get? big-map { a: a, b: b, c: c })
    (map-set big-map { a: a, b: b, c: c } { a: a, b: b, c: c })
    (map-get? big-map { a: a, b: b, c: c })
    (map-set big-map { a: a, b: b, c: c } { a: a, b: b, c: c })
    (map-get? big-map { a: a, b: b, c: c })
    (map-set big-map { a: a, b: b, c: c } { a: a, b: b, c: c })
    (map-get? big-map { a: a, b: b, c: c })
    (map-set big-map { a: a, b: b, c: c } { a: a, b: b, c: c })
    (map-get? big-map { a: a, b: b, c: c })
    (map-set big-map { a: a, b: b, c: c } { a: a, b: b, c: c })
    (ok true)
  )
)
