// Copyright 2017 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Elliptic curve operations on Curve25519.

use {bssl, c, error};

// Keep this in sync with `fe` in curve25519/internal.h.
pub type Elem = [i32; ELEM_LIMBS];
const ELEM_LIMBS: usize = 10;
pub const ELEM_LEN: usize = 32;

// Keep this in sync with `ge_p3` in curve25519/internal.h.
#[repr(C)]
pub struct ExtPoint {
    x: Elem,
    y: Elem,
    z: Elem,
    t: Elem,
}

impl ExtPoint {
    pub fn new_at_infinity() -> Self {
        ExtPoint {
            x: [0; ELEM_LIMBS],
            y: [0; ELEM_LIMBS],
            z: [0; ELEM_LIMBS],
            t: [0; ELEM_LIMBS],
        }
    }

    pub fn from_bytes_vartime(bytes: &[u8; ELEM_LEN])
                              -> Result<Self, error::Unspecified> {
        let mut point = Self::new_at_infinity();

        try!(bssl::map_result(unsafe {
            GFp_x25519_ge_frombytes_vartime(&mut point, bytes)
        }));

        Ok(point)
    }

    pub fn to_bytes(&self) -> [u8; ELEM_LEN] {
        point_to_bytes(&self.x, &self.y, &self.z)
    }

    pub fn invert_vartime(&mut self) {
        for i in 0..ELEM_LIMBS {
            self.x[i] = -self.x[i];
            self.t[i] = -self.t[i];
        }
    }
}

// Keep this in sync with `ge_p2` in curve25519/internal.h.
#[repr(C)]
pub struct Point {
    x: Elem,
    y: Elem,
    z: Elem,
}

impl Point {
    pub fn new_at_infinity() -> Self {
        Point {
            x: [0; ELEM_LIMBS],
            y: [0; ELEM_LIMBS],
            z: [0; ELEM_LIMBS],
        }
    }

    pub fn to_bytes(&self) -> [u8; ELEM_LEN] {
        point_to_bytes(&self.x, &self.y, &self.z)
    }
}

fn point_to_bytes(x: &Elem, y: &Elem, z: &Elem) -> [u8; ELEM_LEN] {
    let mut recip = [0; ELEM_LIMBS];
    let mut x_over_z = [0; ELEM_LIMBS];
    let mut y_over_z = [0; ELEM_LIMBS];
    let mut bytes = [0; ELEM_LEN];

    unsafe {
        GFp_fe_invert(&mut recip, z);
        GFp_fe_mul(&mut x_over_z, x, &recip);
        GFp_fe_mul(&mut y_over_z, y, &recip);
        GFp_fe_tobytes(&mut bytes, &y_over_z);
    }
    bytes[31] ^= unsafe { GFp_fe_isnegative(&x_over_z) << 7 };

    bytes
}

extern {
    fn GFp_fe_invert(out: &mut Elem, z: &Elem);
    fn GFp_fe_isnegative(elem: &Elem) -> u8;
    fn GFp_fe_mul(h: &mut Elem, f: &Elem, g: &Elem);
    fn GFp_fe_tobytes(bytes: &mut [u8; ELEM_LEN], elem: &Elem);
    fn GFp_x25519_ge_frombytes_vartime(h: &mut ExtPoint, s: &[u8; ELEM_LEN])
                                       -> c::int;
}
