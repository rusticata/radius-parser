//! # radius-parser
//!
//! [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
//! [![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
//! [![Build Status](https://travis-ci.org/rusticata/radius-parser.svg?branch=master)](https://travis-ci.org/rusticata/radius-parser)
//! [![Crates.io Version](https://img.shields.io/crates/v/radius-parser.svg)](https://crates.io/crates/radius-parser)
//!
//! ## Overview
//!
//! radius-parser is a parser for the Radius protocol.
//!
//! This crate mostly serves as a demo/example crate for network protocol parsers written using nom, and nom-derive.

#![deny(
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications
)]

mod radius;
mod radius_attr;
pub use radius::*;
pub use radius_attr::*;

pub use nom;
