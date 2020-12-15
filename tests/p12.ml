
let cert_equal a b =
  let a = X509.Certificate.subject a in
  let b = X509.Certificate.subject b in
  X509.Distinguished_name.equal a b

let cert_testable = Alcotest.testable X509.Certificate.pp cert_equal

let key_equal a b =
  let a = Mirage_crypto_pk.Rsa.sexp_of_priv a in
  let b = Mirage_crypto_pk.Rsa.sexp_of_priv b in
  Sexplib.Sexp.equal a b

let key_pp fmt k =
  Sexplib.Sexp.pp_hum fmt (Mirage_crypto_pk.Rsa.sexp_of_priv k)
   
let key_testable = Alcotest.testable key_pp key_equal


let test_decode_openssl_pfx () =
  (* file testcertificates/ca.p12.pem has been created with:
   * export OPENSSL_CONF=$(realpath openssl.cnf)
   * openssl pkcs12 -export -inkey private/cakey.pem -in cacert.pem -out ca.p12.pem -passout pass: *)
  let ca_p12 = X509tests.with_loaded_file "ca.p12" ~f:X509.PKCS12.decode_der in
  (* Fmt.pr "%a" X509.PKCS12.pp ca_p12;
   * assert (1=2); *)
  let data = X509.PKCS12.verify "" ca_p12 in
  let cert, priv_key = match data with
    | Error (`Msg e) -> Alcotest.failf "decrypting error: %s" e
    | Ok [`Certificate cert; `Decrypted_private_key priv_key; ]
    | Ok [`Decrypted_private_key priv_key; `Certificate cert; ] ->
      cert, priv_key
    | _ -> Alcotest.failf "Something unexpected found in ca.p12"
  in
  (* let exp_cert = X509tests.first_cert "first" in *)
  let exp_cert = X509tests.cacert in
  Alcotest.check cert_testable "Check cacert from p12 equals to source"
    exp_cert cert;
  let priv_key = match priv_key with | `RSA k -> k in
  let exp_priv_key = X509tests.priv in
  Alcotest.check key_testable "Check private key from p12 equals to source" exp_priv_key priv_key


let test_encode_and_decode_pfx password priv_key cert () =
  let open X509.PKCS12 in
  let cert_hash = X509.Certificate.fingerprint `SHA1 cert in
  (* let key_bag = safe_bag_private_key priv_key in *)
  let key_bag = safe_bag_pkcs8shrouded_key
      ~attrs:[`LocalKeyId cert_hash] ~password priv_key
                |> Rresult.R.failwith_error_msg in
  let cert_bag = safe_bag_certificate
      ~attrs:[`LocalKeyId cert_hash] cert in
  let safe_contents = [
    content_info_data [key_bag];
    content_info_encrypted ~password [cert_bag]
    |> Rresult.R.failwith_error_msg;
  ] in
  let pfx = create ~password safe_contents in
  let pfx_der = encode_der pfx in
  if Cstruct.len pfx_der < 100 then
    Alcotest.fail "Could not encode pfx_der ";
  let pfx = decode_der pfx_der |> Rresult.R.failwith_error_msg in
  let data = verify password pfx in
  let dec_cert, dec_priv_key = match data with
    | Error (`Msg e) -> Alcotest.failf "decrypting error: %s" e
    | Ok [`Certificate cert; `Decrypted_private_key priv_key; ]
    | Ok [`Decrypted_private_key priv_key; `Certificate cert; ] ->
      cert, priv_key
    | _ -> Alcotest.failf "Something unexpected found in ca.p12"
  in
  Alcotest.check cert_testable "Check cacert from p12 equals to source"
    cert dec_cert;
  let dec_priv_key = match dec_priv_key with | `RSA k -> k in
  Alcotest.check key_testable "Check private key from p12 equals to source" priv_key dec_priv_key
  (* Fmt.pr "%a" X509.PKCS12.pp pfx;
   * Alcotest.fail "DBG" *)


let tests = [
  "Test encrypted by openssl", `Quick, test_decode_openssl_pfx;
  "Test encode and decode back", `Quick,
  test_encode_and_decode_pfx "" X509tests.priv X509tests.cacert;
]
