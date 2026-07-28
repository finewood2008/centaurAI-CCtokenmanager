use tokio::sync::oneshot;

const DIALOG_CLOSED_ERROR: &str = "文件选择器异常关闭";

/// Bridge a callback-based native dialog to an async Tauri command.
///
/// Native dialogs must be opened with the dialog plugin's non-blocking API so
/// their event loop is created on the GUI thread. Waiting on this oneshot
/// yields the Tokio task instead of occupying a blocking worker for the entire
/// lifetime of the dialog.
pub(crate) async fn await_dialog_result<T, F>(open_dialog: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(Box<dyn FnOnce(T) + Send>),
{
    let (sender, receiver) = oneshot::channel();
    open_dialog(Box::new(move |result| {
        let _ = sender.send(result);
    }));

    receiver.await.map_err(|_| DIALOG_CLOSED_ERROR.to_string())
}

#[cfg(test)]
mod tests {
    use super::await_dialog_result;

    #[tokio::test]
    async fn resolves_with_the_dialog_callback_result() {
        let result = await_dialog_result(|complete| complete(Some("selected"))).await;

        assert_eq!(result.unwrap(), Some("selected"));
    }

    #[tokio::test]
    async fn preserves_a_cancelled_dialog_result() {
        let result = await_dialog_result(|complete| complete(None::<String>)).await;

        assert_eq!(result.unwrap(), None);
    }

    #[tokio::test]
    async fn reports_when_the_dialog_drops_its_callback() {
        let result = await_dialog_result::<Option<String>, _>(drop).await;

        assert_eq!(result.unwrap_err(), "文件选择器异常关闭");
    }
}
