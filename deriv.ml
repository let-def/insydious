(* Primitives for working with 8-bit and 32-bit integers.
   (portable semantics for bit twiddling assuming at least 32-bit integers)
*)
let (lnot) = fun x -> x lxor 0xFFFFFFFF
let byte i n = (i lsr (n * 8)) land 0xFF
let get_uint8 b i = b.(i) land 0xFF
let set_uint8 b i c = b.(i) <- c land 0xFF
let get_int32_be b i =
  let b0 = get_uint8 b (i + 0) in
  let b1 = get_uint8 b (i + 1) in
  let b2 = get_uint8 b (i + 2) in
  let b3 = get_uint8 b (i + 3) in
  (b0 lsl 24) lor (b1 lsl 16) lor (b2 lsl 8) lor b3

let set_int32_be b i c =
  let b0 = byte c 0 in
  let b1 = byte c 1 in
  let b2 = byte c 2 in
  let b3 = byte c 3 in
  set_uint8 b (i + 0) b3;
  set_uint8 b (i + 1) b2;
  set_uint8 b (i + 2) b1;
  set_uint8 b (i + 3) b0

let mul = ( * )

let array_init = Array.init
let array_copy = Array.copy

(* Other primitives (quick'n'dirty emulation for Js)

   let array_init i f =
    let a = Array.make i (Obj.magic ()) in
    a.(i) <- f i;
    a

   let array_copy a =
    let len = Array.length a in
    let b = Array.make len a.(0) in
    for i = 1 to len - 1 do
      b.(i) <- a.(i)
    done;
    b

   let (mod) x y =
    let x = ref x in
    while !x >= y do
      x := !x - y
    done;
    !x

   let mul x y =
    let acc = ref 0 in
    let mn, mx = if x < y then x, y else y, x in
    for i = 1 to mn do acc := !acc + mx done;
    !acc
*)

(* Pass 1: (almost certainly...) sha256 *)

let sha256_constants: int array = [|
  0x428A2F98; 0x71374491; 0xB5C0FBCF; 0xE9B5DBA5;
  0x3956C25B; 0x59F111F1; 0x923F82A4; 0xAB1C5ED5;
  0xD807AA98; 0x12835B01; 0x243185BE; 0x550C7DC3;
  0x72BE5D74; 0x80DEB1FE; 0x9BDC06A7; 0xC19BF174;
  0xE49B69C1; 0xEFBE4786; 0x0FC19DC6; 0x240CA1CC;
  0x2DE92C6F; 0x4A7484AA; 0x5CB0A9DC; 0x76F988DA;
  0x983E5152; 0xA831C66D; 0xB00327C8; 0xBF597FC7;
  0xC6E00BF3; 0xD5A79147; 0x06CA6351; 0x14292967;
  0x27B70A85; 0x2E1B2138; 0x4D2C6DFC; 0x53380D13;
  0x650A7354; 0x766A0ABB; 0x81C2C92E; 0x92722C85;
  0xA2BFE8A1; 0xA81A664B; 0xC24B8B70; 0xC76C51A3;
  0xD192E819; 0xD6990624; 0xF40E3585; 0x106AA070;
  0x19A4C116; 0x1E376C08; 0x2748774C; 0x34B0BCB5;
  0x391C0CB3; 0x4ED8AA4A; 0x5B9CCA4F; 0x682E6FF3;
  0x748F82EE; 0x78A5636F; 0x84C87814; 0x8CC70208;
  0x90BEFFFA; 0xA4506CEB; 0xBEF9A3F7; 0xC67178F2;
|]

let sha256_iv: int array = [|
  0x6A09E667; 0xBB67AE85; 0x3C6EF372; 0xA54FF53A;
  0x510E527F; 0x9B05688C; 0x1F83D9AB; 0x5BE0CD19;
|]

(* Specialised for 10 bytes key *)
let sha256 (key: int array): int array =
  let obuf = Array.make 64 0 in
  for i = 0 to 9 do set_uint8 obuf i (key.(i)); done;
  set_uint8 obuf 10 0x80;
  set_uint8 obuf 63 80;
  let tmp = Array.make 64 0 in
  for i = 0 to 15 do
    tmp.(i) <- get_int32_be obuf (i * 4)
  done;
  let int32 a = a land 0xFFFFFFFF in
  let slr t l r = (t lsl l) lor (t lsr r) in
  for i = 16 to 63 do
    let t0 = tmp.(i - 15) and td = tmp.(i - 2) in
    let t0_1 = slr t0 0x0e 0x12 in
    let t0_2 = slr t0 0x19 0x07 in
    let t0_3 = t0 lsr 0x03      in
    let td_1 = slr td 0x0f 0x11 in
    let td_2 = slr td 0x0d 0x13 in
    let td_3 = td lsr 0x0a      in
    tmp.(i) <- int32 @@
      (tmp.(i - 0x07) + (t0_1 lxor t0_2 lxor t0_3) +
       tmp.(i - 0x10) + (td_1 lxor td_2 lxor td_3))
  done;
  let sbuf = array_copy sha256_iv in
  for i = 0 to 63 do
    let s6 = sbuf.(6) in
    let s5 = sbuf.(5) in
    let s4 = sbuf.(4) in
    let tmp =
      int32 @@
      sha256_constants.(i) + tmp.(i) + sbuf.(7) +
      ((lnot s4 land s6) lxor (s5 land s4)) +
      (slr s4 0x15 0x0b lxor slr s4 0x07 0x19 lxor slr s4 0x1a 0x06)
    in
    sbuf.(7) <- s6; sbuf.(6) <- s5; sbuf.(5) <- s4;
    sbuf.(4) <- int32 @@ sbuf.(3) + tmp;
    let s0 = sbuf.(0) and s1 = sbuf.(1) and s2 = sbuf.(2) in
    sbuf.(3) <- s2; sbuf.(2) <- s1; sbuf.(1) <- s0;
    sbuf.(0) <-
      int32 @@
      (slr s0 0x13 0x0d lxor slr s0 0x0a 0x16 lxor slr s0 0x1e 0x02) +
      (((s1 lxor s0) land s2) lxor (s1 land s0)) + tmp
  done;
  let result = Array.make 32 0 in
  for i = 0 to 7 do
    set_int32_be result (i * 4) (sbuf.(i) + sha256_iv.(i))
  done;
  result

(* Pass 2: AES-like, probably with custom sauce? *)

let rijndael_sbox: int array = [|
  0x63;0x7C;0x77;0x7B;0xF2;0x6B;0x6F;0xC5;0x30;0x01;0x67;0x2B;0xFE;0xD7;0xAB;0x76;
  0xCA;0x82;0xC9;0x7D;0xFA;0x59;0x47;0xF0;0xAD;0xD4;0xA2;0xAF;0x9C;0xA4;0x72;0xC0;
  0xB7;0xFD;0x93;0x26;0x36;0x3F;0xF7;0xCC;0x34;0xA5;0xE5;0xF1;0x71;0xD8;0x31;0x15;
  0x04;0xC7;0x23;0xC3;0x18;0x96;0x05;0x9A;0x07;0x12;0x80;0xE2;0xEB;0x27;0xB2;0x75;
  0x09;0x83;0x2C;0x1A;0x1B;0x6E;0x5A;0xA0;0x52;0x3B;0xD6;0xB3;0x29;0xE3;0x2F;0x84;
  0x53;0xD1;0x00;0xED;0x20;0xFC;0xB1;0x5B;0x6A;0xCB;0xBE;0x39;0x4A;0x4C;0x58;0xCF;
  0xD0;0xEF;0xAA;0xFB;0x43;0x4D;0x33;0x85;0x45;0xF9;0x02;0x7F;0x50;0x3C;0x9F;0xA8;
  0x51;0xA3;0x40;0x8F;0x92;0x9D;0x38;0xF5;0xBC;0xB6;0xDA;0x21;0x10;0xFF;0xF3;0xD2;
  0xCD;0x0C;0x13;0xEC;0x5F;0x97;0x44;0x17;0xC4;0xA7;0x7E;0x3D;0x64;0x5D;0x19;0x73;
  0x60;0x81;0x4F;0xDC;0x22;0x2A;0x90;0x88;0x46;0xEE;0xB8;0x14;0xDE;0x5E;0x0B;0xDB;
  0xE0;0x32;0x3A;0x0A;0x49;0x06;0x24;0x5C;0xC2;0xD3;0xAC;0x62;0x91;0x95;0xE4;0x79;
  0xE7;0xC8;0x37;0x6D;0x8D;0xD5;0x4E;0xA9;0x6C;0x56;0xF4;0xEA;0x65;0x7A;0xAE;0x08;
  0xBA;0x78;0x25;0x2E;0x1C;0xA6;0xB4;0xC6;0xE8;0xDD;0x74;0x1F;0x4B;0xBD;0x8B;0x8A;
  0x70;0x3E;0xB5;0x66;0x48;0x03;0xF6;0x0E;0x61;0x35;0x57;0xB9;0x86;0xC1;0x1D;0x9E;
  0xE1;0xF8;0x98;0x11;0x69;0xD9;0x8E;0x94;0x9B;0x1E;0x87;0xE9;0xCE;0x55;0x28;0xDF;
  0x8C;0xA1;0x89;0x0D;0xBF;0xE6;0x42;0x68;0x41;0x99;0x2D;0x0F;0xB0;0x54;0xBB;0x16;
|]

let pass_2_secret: int array =
  [| 0x8D;0x01;0x02;0x04;0x08;0x10;0x20;0x40;
     0x80;0x1B;0x36;0x6C;0xD8;0xAB;0x4D;0x9A |]

let pass_2_1 (input: int array): int array =
  let len = Array.length input in
  let idx = input.(9) land 0xf in
  array_init 16 (fun i -> input.((mul i (idx * 2 + 1)) mod len))

let pass_2_2 (input: int array): int array =
  array_init 16 (fun idx ->
      let i = idx lsr 2 and j = idx land 3 in
      let acc = ref 0 in
      for k = 0 to 7 do
        let c1 = input.(i * 8 + k) and c2 = input.(k * 4 + j) in
        acc := !acc + mul c1 c2
      done;
      !acc land 0xFF
    )

let pass_2_switch_0 (input: int array): int array =
  array_init 16 (fun idx ->
      let i = 3 - idx lsr 2 and j = idx land 3 in
      input.(j * 4 + i)
    )

let pass_2_switch_1 (input: int array): int array =
  array_init 16 (fun idx ->
      let i = idx lsr 2 and j = 3 - idx land 3 in
      input.(j * 4 + i)
    )

let pass_2_switch_2 (input: int array): int array =
  array_init 16 (fun idx ->
      let i = idx lsr 2 and j = idx land 3 in
      let c = input.((j + i) land 3 + i * 4) in
      ((c + i) land 0xFF)
    )

let pass_2_switch_3 (input: int array): int array =
  let acc1 = ref 0 and acc2 = ref 0 in
  for i = 0 to 3 do
    acc1 := !acc1 lxor input.(i * 5);
    acc2 := !acc2 lxor input.(i * 3 + 3);
  done;
  let acc1 = !acc1 and acc2 = !acc2 in
  array_init 16
    (fun i -> input.(i) lxor (if i land 1 = 0 then acc1 else acc2))

let pass_2_switch_4 (input: int array): int array =
  array_init 16 (fun i ->
      let c1 = input.(i) and c2 = input.((i+1) land 0xF) in
      c1 lxor (if c2 < c1 then c2 else 0xFF)
    )

let pass_2_switch_5 (input: int array): int array =
  let buf = Array.make 16 0 in
  for i = 0 to 3 do
    let acc = ref 0 in
    for j = 0 to 3 do acc := !acc lxor input.(4 * j + i) done;
    for j = 0 to 3 do
      let idx = 4 * j + i in
      buf.(idx) <- ((mul input.(idx) !acc) land 0xFF)
    done
  done;
  buf

let pass_2_3 (scratch: int array) (buf: int array) (offset: int): unit =
  let o = (offset land 0xFF) lsl 4 in
  for i = 0 to 15 do
    set_uint8 buf i
      (get_uint8 buf i lxor get_uint8 scratch (o + i))
  done

let pass_2_permute (buf: int array): unit =
  for i = 0 to 15 do set_uint8 buf i rijndael_sbox.(get_uint8 buf i) done;
  let b01 = get_uint8 buf 0x01 in
  set_uint8 buf 0x01 (get_uint8 buf 0x05);
  set_uint8 buf 0x05 (get_uint8 buf 0x09);
  let b0d = get_uint8 buf 0x0d in
  set_uint8 buf 0x0d b01;
  let b02 = get_uint8 buf 0x02 in
  set_uint8 buf 0x09 b0d;
  set_uint8 buf 0x02 (get_uint8 buf 0x0a);
  set_uint8 buf 0x0a b02;
  let b06 = get_uint8 buf 0x06 in
  set_uint8 buf 0x06 (get_uint8 buf 0x0e);
  set_uint8 buf 0x0e b06;
  let b03 = get_uint8 buf 0x03 in
  set_uint8 buf 0x03 (get_uint8 buf 0x0f);
  set_uint8 buf 0x0f (get_uint8 buf 0x0b);
  let b07 = get_uint8 buf 0x07 in
  set_uint8 buf 0x07 b03;
  set_uint8 buf 0x0b b07

let pass_2_4 (scratch: int array) (input: int array): int array =
  let buf = array_copy input in
  pass_2_3 scratch buf 0;
  for i = 1 to 9 do
    pass_2_permute buf;
    for j = 0 to 3 do
      let j = j * 4 in
      let p0 = get_uint8 buf (j + 0) in
      let p1 = get_uint8 buf (j + 1) in
      let p2 = get_uint8 buf (j + 2) in
      let p3 = get_uint8 buf (j + 3) in
      let p23 = p2 lxor p3 in
      let x = -((p0 lxor p1) lsr 7) land 27 in
      let y = -((p2 lxor p1) lsr 7) land 27 in
      let z = -(p23 lsr 7) land 27 in
      let w = -((p3 lxor p0) lsr 7) land 27 in
      set_uint8 buf (j + 0)
        (x lxor ((p0 lxor p1) * 2) lxor p1 lxor p23);
      set_uint8 buf (j + 1)
        (y lxor ((p2 lxor p1) * 2) lxor p0 lxor p23);
      set_uint8 buf (j + 2)
        (z lxor (p23 * 2) lxor p0 lxor p1 lxor p3);
      set_uint8 buf (j + 3)
        (w lxor ((p3 lxor p0) * 2) lxor p0 lxor p1 lxor p2);
    done;
    pass_2_3 scratch buf i;
  done;
  pass_2_permute buf;
  pass_2_3 scratch buf 10;
  buf

let pass_2 (input: int array): int array =
  let scram_1 = pass_2_1 input in
  let scram_2 =
    let scram_2 = pass_2_2 input in
    match input.(8) mod 6 with
    | 0 -> pass_2_switch_0 scram_2
    | 1 -> pass_2_switch_1 scram_2
    | 2 -> pass_2_switch_2 scram_2
    | 3 -> pass_2_switch_3 scram_2
    | 4 -> pass_2_switch_4 scram_2
    | _ -> pass_2_switch_5 scram_2
  in
  let scratch = Array.make 180 0 in
  for i = 0 to 15 do set_uint8 scratch i scram_2.(i) done;
  for i = 4 to 43 do
    let i = i * 4 in
    let b0 = get_uint8 scratch (i - 4) in
    let b1 = get_uint8 scratch (i - 3) in
    let b2 = get_uint8 scratch (i - 2) in
    let b3 = get_uint8 scratch (i - 1) in
    let b0, b1, b2, b3 =
      if (i land 12) = 0 then (
        get_uint8 rijndael_sbox b1 lxor get_uint8 pass_2_secret (i / 16),
        get_uint8 rijndael_sbox b2,
        get_uint8 rijndael_sbox b3,
        get_uint8 rijndael_sbox b0
      ) else
        (b0, b1, b2, b3)
    in
    set_uint8 scratch (i + 0) (get_uint8 scratch (i - 16) lxor b0);
    set_uint8 scratch (i + 1) (get_uint8 scratch (i - 15) lxor b1);
    set_uint8 scratch (i + 2) (get_uint8 scratch (i - 14) lxor b2);
    set_uint8 scratch (i + 3) (get_uint8 scratch (i - 13) lxor b3);
  done;
  pass_2_4 scratch scram_1

(* Pass 3: (almost certainly...) CRC64 *)

let crc64_hi: int = 0xC96C5795

let crc64_lo: int = 0xD7870F42

let crc64_table: int array =
  let arr = Array.make 512 0 in
  for i = 0 to 255 do
    let acc1 = ref 0 in
    let acc2 = ref i in
    for i = 0 to 7 do
      let acc1' = !acc1 lsr 1 in
      let acc2' = !acc2 lsr 1 lor ((!acc1 land 1) lsl 31) in
      if !acc2 land 1 = 0 then (
        acc1 := acc1';
        acc2 := acc2';
      ) else (
        acc1 := acc1' lxor crc64_hi;
        acc2 := acc2' lxor crc64_lo;
      )
    done;
    arr.(2 * i + 0) <- !acc1;
    arr.(2 * i + 1) <- !acc2;
  done;
  arr

let crc64 (input: int array): int array =
  let acc1 = ref 0 in
  let acc2 = ref 0 in
  for i = 0 to 15 do
    let c = input.(i) in
    let acc1' = (!acc1 lsr 8) in
    let acc2' = (!acc2 lsr 8) lor ((!acc1 land 0xFF) lsl 24) in
    let ofs = (!acc2 land 0xFF) lxor c in
    acc1 := acc1' lxor crc64_table.(ofs * 2 + 0);
    acc2 := acc2' lxor crc64_table.(ofs * 2 + 1);
  done;
  let acc1 = !acc1 and acc2 = !acc2 in
  let result = Array.make 8 0 in
  set_int32_be result 0 acc1;
  set_int32_be result 4 acc2;
  result

let raw_unlock (key: int array): int array =
  crc64 (pass_2 (sha256 key))

let to_hex (c: int): char =
  Char.chr (if c <= 9 then Char.code '0' + c else Char.code 'a' + c - 10)

let unlock (str: string): string =
  let array str = Array.init (String.length str) (fun i -> Char.code str.[i]) in
  let code = raw_unlock (array str) in
  let bytes = Bytes.make 16 '\000' in
  for i = 0 to 7 do
    let c = code.(i) in
    let c0 = c lsr 4 and c1 = c land 0xF in
    Bytes.set bytes (2 * i + 0) (to_hex c0);
    Bytes.set bytes (2 * i + 1) (to_hex c1);
  done;
  Bytes.to_string bytes

let () =
  let open Js_of_ocaml in
  Js.export "unlock" (fun key -> Js.string (unlock (Js.to_string  key)))
