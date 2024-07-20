use std::net::Shutdown;

#[cfg(windows)]
use std::net::TcpStream;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

#[cfg(windows)]
pub struct Stream {
    pub stream: TcpStream,
}

#[cfg(unix)]
pub struct Stream {
    pub stream: UnixStream,
}

//#[cfg(windows)]
impl Stream {
    pub fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
        self.stream.shutdown(how)
    }

    pub fn try_clone(&self) -> std::io::Result<Self> {
        let stream = self.stream.try_clone()?;
        Ok(Stream {stream})
    }
}

/*#[cfg(unix)]
impl Stream {
    pub fn shutdown(&self, _how: Shutdown) -> std::io::Result<()> {
        Ok(())
    }

    pub fn try_clone(&self) -> std::io::Result<Self> {
        let stream = self.stream.try_clone()?;
        Ok(Stream {stream})
    }
}*/

impl std::io::Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

impl std::io::Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}