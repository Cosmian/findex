use std::{ffi::c_uint, sync::Once};

use tracing_subscriber::{layer::SubscriberExt, EnvFilter};

static LOG_INIT: Once = Once::new();

pub(crate) fn log_init(paths: &str, force_logging: c_uint) {
    // We want to log:
    //  - if the environment variable RUST_LOG is defined
    //  - if force_logging is gt 0
    if let Ok(old) = std::env::var("RUST_LOG") {
        LOG_INIT.call_once(|| {
            std::env::set_var("RUST_LOG", format!("{},{}", old, paths));
            tracing_setup();
        });
    } else if force_logging > 0 {
        LOG_INIT.call_once(|| {
            std::env::set_var("RUST_LOG", paths);
            tracing_setup();
        });
    }
}

fn tracing_setup() {
    let layer = tracing_tree::HierarchicalLayer::default()
        .with_verbose_exit(true)
        .with_targets(true)
        .with_thread_names(true)
        .with_thread_ids(true)
        .with_indent_lines(true);
    let (filter, _reload_handle) =
        tracing_subscriber::reload::Layer::new(EnvFilter::from_default_env());

    let subscriber = tracing_subscriber::Registry::default()
        .with(filter)
        .with(layer);

    tracing::subscriber::set_global_default(subscriber).expect("set_global_default failed");
    tracing_log::LogTracer::init().expect("LogTracer init failed");
}
