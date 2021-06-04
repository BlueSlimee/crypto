import gleam/atom.{Atom}
import gleam/bit_string
import gleam/crypto
import gleam/should

external fn ensure_all_started(Atom) -> Result(List(Atom), Nil) =
  "application" "ensure_all_started"

pub fn random_bytes_test() {
  let Ok(_) = ensure_all_started(atom.create_from_string("crypto"))
  crypto.strong_random_bytes(0)
  |> should.equal(bit_string.from_string(""))
  crypto.strong_random_bytes(10)
  |> bit_string.byte_size()
  |> should.equal(10)
}

pub fn run_hmac_test() {
  <<"Aladin":utf8>>
  |> crypto.hmac(crypto.Sha256, <<"secret":utf8>>)
  |> should.equal(<<
    207, 2, 100, 225, 165, 99, 237, 213, 117, 62, 198, 249, 0, 167, 50, 19, 252,
    90, 253, 61, 172, 62, 242, 192, 139, 123, 55, 112, 73, 102, 192, 171,
  >>)
}

pub fn run_hash_test() {
  <<"Здравствуйте!":utf8>>
  |> crypto.hash(crypto.Sha256, _)
  |> should.equal(<<
    146, 214, 164, 236, 192, 147, 44, 240, 21, 70, 210, 147, 95, 225, 60, 232, 184,
    57, 186, 223, 210, 131, 54, 229, 75, 144, 114, 24, 108, 34, 65, 181,
  >>)

  "😵‍💫"
  |> crypto.hash_string(crypto.Sha256, _)
  |> should.equal(<<
    81, 39, 32, 4, 190, 198, 248, 237, 222, 183, 49, 65, 53, 2, 64, 90, 171, 225,
    120, 81, 161, 82, 128, 84, 190, 117, 119, 254, 167, 55, 68, 71,
  >>)
}

pub fn secure_compare_test() {
  crypto.secure_compare(
    bit_string.from_string("ab"),
    bit_string.from_string("ab"),
  )
  |> should.equal(True)

  crypto.secure_compare(
    bit_string.from_string("ab"),
    bit_string.from_string("az"),
  )
  |> should.equal(False)

  crypto.secure_compare(bit_string.from_string(""), bit_string.from_string(""))
  |> should.equal(True)

  crypto.secure_compare(
    bit_string.from_string("ab"),
    bit_string.from_string("a"),
  )
  |> should.equal(False)
}
