
#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    };

    use tokio::sync::Notify;

    use crate::{
        context::{Context as _, SignerEvent, SignerSignal},
        testing::context::*,
    };

    /// This test shows that cloning a context and signalling on the original
    /// context will also signal on the cloned context. But it also demonstrates
    /// that there can be timing issues (particularly in tests) when signalling
    /// across threads/clones, and shows how to handle that.
    #[tokio::test]
    async fn context_clone_signalling_works() {
        // Create a context.
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        // Clone the context.
        let context_clone = context.clone();

        // Get the receiver from the cloned context.
        let mut cloned_receiver = context_clone.get_signal_receiver();

        // Create a counter to track how many signals are received and some
        // Notify channels so that we ensure we don't hit timing issues.
        let recv_count = Arc::new(AtomicU8::new(0));
        let task_started = Arc::new(Notify::new());
        let task_completed = Arc::new(Notify::new());

        // Spawn a task that will receive a signal (and clone values that will
        // be used in the `move` closure). We will receive on the cloned context.
        let task_started_clone = Arc::clone(&task_started);
        let task_completed_clone = Arc::clone(&task_completed);
        let recv_count_clone = Arc::clone(&recv_count);
        tokio::spawn(async move {
            task_started_clone.notify_one();
            let signal = cloned_receiver.recv().await.unwrap();

            assert_eq!(
                signal,
                SignerSignal::Event(SignerEvent::BitcoinBlockObserved)
            );

            recv_count_clone.fetch_add(1, Ordering::Relaxed);
            task_completed_clone.notify_one();
        });

        // This wait is needed to ensure that the `recv_task` is started and
        // the receiver subscribed before we send the signal. Otherwise, the
        // signal may be sent before the receiver is ready to receive it,
        // failing the test.
        task_started.notified().await;

        // Signal the original context.
        context
            .signal(SignerEvent::BitcoinBlockObserved.into())
            .unwrap();

        // This wait is needed to ensure that the below `abort()` doesn't
        // kill the task before it has a chance to update `recv_count`.
        task_completed.notified().await;

        // Ensure that the signal was received.
        assert_eq!(recv_count.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}
