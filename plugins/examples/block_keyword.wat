;; Example WebFilter rule plugin (SPEC_EXT_OPS O10): blocks any request whose request view contains
;; "/ads" (for example a path segment). Plugins can only add blocks; return 0 = no opinion, 1 = block.
;;
;; ABI: export `memory`, `wf_alloc(len) -> ptr` (where the host writes the JSON request view) and
;; `wf_decide(ptr, len) -> 0|1`. No imports are allowed. Enable with:
;;   [[plugins]]
;;   name = "ads"
;;   path = "plugins/examples/block_keyword.wat"
;;   enabled = true
;; and a binary built with `cargo build --release --features plugins`.
(module
  (memory (export "memory") 1)
  ;; One fixed buffer is enough: every call gets a fresh instance.
  (func (export "wf_alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "wf_decide") (param $p i32) (param $n i32) (result i32)
    (local $i i32) (local $end i32)
    (local.set $end (i32.sub (i32.add (local.get $p) (local.get $n)) (i32.const 4)))
    (local.set $i (local.get $p))
    (block $done
      (loop $scan
        (br_if $done (i32.gt_s (local.get $i) (local.get $end)))
        (if (i32.and
              (i32.and (i32.eq (i32.load8_u (local.get $i)) (i32.const 47))             ;; '/'
                       (i32.eq (i32.load8_u offset=1 (local.get $i)) (i32.const 97)))   ;; 'a'
              (i32.and (i32.eq (i32.load8_u offset=2 (local.get $i)) (i32.const 100))  ;; 'd'
                       (i32.eq (i32.load8_u offset=3 (local.get $i)) (i32.const 115)))) ;; 's'
          (then (return (i32.const 1))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)))
    (i32.const 0)))
