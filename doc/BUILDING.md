To test building on FreeBSD:

  vagrant init freebsd/FreeBSD-10.3-RELEASE
  vagrant up --provider virtualbox

This may show an error related to MAC addresses, but just try again:

  vagrant up
  vagrant ssh
  sudo pkg install git gmake
  git clone https://github.com/raboof/nethogs
  cd nethogs
  gmake
  sudo ./src/nethogs
