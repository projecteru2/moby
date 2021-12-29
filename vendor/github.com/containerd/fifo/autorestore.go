package fifo

import (
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// OpenFifo opens a fifo. Returns io.ReadWriteCloser.
// Context can be used to cancel this function until open(2) has not returned.
// Accepted flags:
// - syscall.O_CREAT - create new fifo if one doesn't exist
// - syscall.O_RDONLY - open fifo only from reader side
// - syscall.O_WRONLY - open fifo only from writer side
// - syscall.O_RDWR - open fifo from both sides, never block on syscall level
// - syscall.O_NONBLOCK - return io.ReadWriteCloser even if other side of the
//     fifo isn't open. read/write will be connected after the actual fifo is
//     open or after fifo is closed.
func OpenAutoRestoreFifo(fn string, flag int, perm os.FileMode) (io.ReadCloser, error) {
	if _, err := os.Stat(fn); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if flag&syscall.O_CREAT == 0 {
			return nil, err
		}
		if err := syscall.Mkfifo(fn, uint32(perm&os.ModePerm)); err != nil && !os.IsExist(err) {
			return nil, errors.Wrapf(err, "error creating fifo %v", fn)
		}
	}

	lock := &sync.Mutex{}
	holder := &fifoHolder{
		cond: sync.NewCond(lock),
		fn:   fn,
		flag: flag,
		perm: perm,
	}
	holder.openFifoAsync(nil)

	return holder, nil
}

type fifoHolder struct {
	cond *sync.Cond

	fn   string
	flag int
	perm os.FileMode

	handle  *handle
	fifo    io.ReadCloser
	err     error
	opening bool
	closed  bool
}

func (f *fifoHolder) Read(p []byte) (n int, err error) {
	fifo, err := f.getFifo()
	if err != nil {
		return 0, err
	}
	if fifo == nil {
		if fifo, err = f.waitFifoOpen(); err != nil {
			return 0, err
		}
	}
	cnt, err := fifo.Read(p)
	if err != nil {
		f.openFifoAsync(fifo)
	}
	return cnt, nil
}

func (f *fifoHolder) Close() error {
	f.cond.L.Lock()
	defer f.cond.L.Unlock()

	if f.closed {
		return nil
	}
	f.closed = true
	f.err = ErrClosed

	if f.handle != nil {
		logrus.Debugf("fifo is opening, open writer side, %s", f.fn)
		go func(handle *handle, flag int, perm os.FileMode) {
			flag &= ^syscall.O_CREAT
			flag &= ^syscall.O_NONBLOCK

			path, err := handle.Path()
			if err != nil {
				return
			}

			fifoFile, err := os.OpenFile(path, flag, perm)
			if err != nil {
				return
			}
			_ = fifoFile.Close()
		}(f.handle, syscall.O_WRONLY, 0700)
	}

	if f.fifo != nil {
		fifo := f.fifo
		f.fifo = nil
		go func() {
			_ = fifo.Close()
		}()
	}
	logrus.Debugf("closed fifo, broadcast, %s", f.fn)
	f.cond.Broadcast()
	return nil
}

func (f *fifoHolder) getFifo() (io.ReadCloser, error) {
	f.cond.L.Lock()
	defer f.cond.L.Unlock()

	return f.fifo, f.err
}

func (f *fifoHolder) waitFifoOpen() (rrc io.ReadCloser, rerr error) {
	f.openFifoAsync(nil)

	f.cond.L.Lock()
	defer f.cond.L.Unlock()

	for f.fifo == nil && f.err == nil {
		f.cond.Wait()
	}

	return f.fifo, f.err
}

func (f *fifoHolder) openFifoAsync(fifo io.ReadCloser) {
	f.cond.L.Lock()
	defer f.cond.L.Unlock()

	if f.opening {
		return
	}

	if fifo != nil {
		logrus.Debugf("close broken fifo, %s", f.fn)
		go func() {
			_ = fifo.Close()
		}()
		if fifo != f.fifo {
			logrus.Debugf("not same fifo file, %s", f.fn)
			f.cond.Broadcast()
			return
		}
		f.fifo = nil
	}

	if f.closed {
		return
	}
	f.opening = true

	go func() {
		fifo, err := f.openFifoReader()
		f.cond.L.Lock()
		defer f.cond.L.Unlock()

		f.opening = false
		if !f.closed {
			logrus.Debugf("broadcast new fifo, %s", f.fn)
			f.fifo = fifo
			f.err = err
			f.cond.Broadcast()
			return
		}

		logrus.Debugf("fifo closed, closed opened fifo, %s", f.fn)
		if fifo != nil {
			_ = fifo.Close()
		}
	}()
}

func (f *fifoHolder) openFifoReader() (file *autorestoreFifo, err error) {
	var (
		flag = f.flag
		perm = f.perm
	)
	flag &= ^syscall.O_CREAT
	flag &= ^syscall.O_NONBLOCK

	var (
		handle *handle
		path   string
	)
	handle, err = getHandle(f.fn)
	if err != nil {
		return nil, err
	}

	f.cond.L.Lock()
	if f.closed {
		f.cond.L.Unlock()
		go func() {
			_ = handle.Close()
		}()
		return nil, ErrClosed
	}
	f.handle = handle
	f.cond.L.Unlock()

	defer func() {
		f.cond.L.Lock()
		defer f.cond.L.Unlock()

		f.handle = nil
		if err != nil {
			_ = handle.Close()
		}
	}()

	path, err = handle.Path()
	if err != nil {
		return nil, err
	}

	fifoFile, err := os.OpenFile(path, flag, perm)
	if err != nil {
		return nil, err
	}
	return &autorestoreFifo{
		file:   fifoFile,
		handle: handle,
	}, nil
}

type autorestoreFifo struct {
	once   sync.Once
	file   *os.File
	handle *handle
}

func (f *autorestoreFifo) Read(p []byte) (n int, err error) {
	return f.file.Read(p)
}

func (f *autorestoreFifo) Close() error {
	f.once.Do(func() {
		_ = f.file.Close()
		_ = f.handle.Close()
	})
	return nil
}
