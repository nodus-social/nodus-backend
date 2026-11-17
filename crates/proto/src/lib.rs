//! The contracts services speak to each other.
//!
//! Each service also serves the same data over HTTP where a browser needs it; the protobuf
//! here is what the instance's own processes use, so a field only appears if some process
//! reads it.

pub mod telemetry {
    tonic::include_proto!("nodus.telemetry");
}
