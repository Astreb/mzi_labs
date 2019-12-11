#include <elliptic.h>
#include <utils.h>
#include <iostream>
#include <tuple>
#include <set>
#include <utility>

// constexpr uint64_t MOD = 1000000007LL;
constexpr int64_t MOD = 127;

typedef ModNumber<int64_t, MOD> Number;
typedef ModPoint<Number> Point;
typedef EllipticCurve<Number, Point> Curve;

int main() {
  // public data
  Number a = 1;
  Number b = 1;
  Curve curve(a, b);
  Point P(7, 4);

  // private data
  int alice_private_key = 17;
  int bob_private_key = 5;

  std::cout << "P = " << P << std::endl;

  // Alice -> Bob
  Point alice_public_key = BinPow(P, alice_private_key, curve);
  std::cout << "a_public = " << alice_public_key << std::endl;

  // Bob -> Alice
  Point bob_public_key = BinPow(P, bob_private_key, curve);
  std::cout << "b_public = " << bob_public_key << std::endl;
  std::cout << std::endl;


  Point common_key;
  // Alice
  Point alice_common_key = BinPow(bob_public_key, alice_private_key, curve);
  std::cout << "a_common_key = " << alice_common_key << std::endl;

  // Bob
  Point bob_common_key = BinPow(alice_public_key, bob_private_key, curve);
  std::cout << "b_common_key = " << bob_common_key << std::endl;

  return 0;
}

