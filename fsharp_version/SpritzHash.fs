// Learn more about F# at http://fsharp.net
// See the 'F# Tutorial' project for more help.

type Spritz() = 
  let mutable i = 0uy
  let mutable j = 0uy
  let mutable k = 0uy
  let mutable z = 0uy
  let mutable a = 0uy
  let mutable w = 1uy
  let mem = [| 0uy .. 255uy |]

  member private this.swap x y =
    let tmp = mem.[x]
    mem.[x] <- mem.[y]
    mem.[y] <- tmp

  member private this.crush =
    for v = 0 to 127 do
      if mem.[v] > mem.[255-v] then this.swap v (255 - v) 

  member private this.update times =
     let mutable mtimes = times
     let mutable mi = i
     let mutable mj = j
     let mutable mk = k
     let mw = w

     while  mtimes > 0 do
        mtimes <- mtimes - 1
        mi <- mi + mw
        mj <- mk + mem.[ int (mj + mem.[ int mi ]) ]
        mk <- mi + mk + mem.[ int mj ]
        this.swap (int mi) (int mj) 

     i <- mi
     j <- mj
     k <- mk

  member private this.whip amt =
    let rec gcd e1 e2 = if e2 = 0 then e1 else gcd e2 (e1%e2)
    this.update amt
    w <- w + 1uy
    while gcd (int w) 256 <> 1 do
      w <- w + 1uy

  member private this.shuffle =
    this.whip 512
    this.crush
    this.whip 512
    this.crush
    this.whip 512
    a <- 0uy

  member private this.absorb_nibble n =
    if a = 128uy then this.shuffle
    this.swap (int a) (int (128uy+n))
    a <- a + 1uy

  member this.absorb  b =
    this.absorb_nibble (b &&& 15uy)
    this.absorb_nibble (b >>> 4)

  member this.absorb_stop  =
    if a = 128uy then this.shuffle
    a <- a + 1uy

  member this.drip =
    if a > 0uy then this.shuffle
    this.update 1
    z <- mem.[int (j + mem.[int (i + mem.[int (z + k)]) ]) ]
    z

let hash_file fn =
    let buffer = Array.create 4096 0uy
    let cipher = new Spritz()
    use fl = new System.IO.BinaryReader(new System.IO.FileStream(fn,System.IO.FileMode.Open))
    let rec fill_cipher () =
      let bytes = fl.Read(buffer,0,4096)
      if bytes <> 0 then do
        for idx in 0 .. (bytes-1) do cipher.absorb buffer.[idx]
        fill_cipher()
    fill_cipher()
    cipher.absorb_stop
    cipher.absorb 32uy
    Array.init 32 (fun _ -> cipher.drip)

let disp_hash (fl, hash) = 
   printf "%s: " fl
   hash |> Array.iter (printf "%02x")
   printfn ""

[<EntryPoint>]
let main argv = 
    argv |> Array.Parallel.map (fun file -> (file, hash_file file)) 
         |> Array.iter disp_hash
    0 // return an integer exit code
