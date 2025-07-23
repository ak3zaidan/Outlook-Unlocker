#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_credential_loader() -> io::Result<()> {
        // 创建临时测试文件
        let mut file = NamedTempFile::new()?;
        writeln!(file, "user1----pass1")?;
        writeln!(file, "user2----pass2")?;
        writeln!(file, "user3----pass3----extra")?;

        let loader = CredentialLoader::new(file.path(), "----")?;

        assert_eq!(loader.get_total_count(), 3);

        if let Some(cred) = loader.next() {
            assert_eq!(cred.username, "user1");
            assert_eq!(cred.password, "pass1");
            assert_eq!(cred.raw_line, "user1----pass1");
        }

        assert_eq!(loader.get_current_index(), 1);

        if let Some(cred) = loader.get_by_index(2) {
            assert_eq!(cred.username, "user3");
            assert_eq!(cred.password, "pass3");
            assert_eq!(cred.raw_line, "user3----pass3----extra");
        }

        Ok(())
    }
}
