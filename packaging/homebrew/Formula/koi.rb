# Homebrew formula for Koi — draft, fills at stable 1.0.0 (see ../README.md)
# Target repo: github.com/sylin-org/homebrew-tap at Formula/koi.rb
class Koi < Formula
  desc "Local connectivity substrate: discover, trust, and connect your LAN"
  homepage "https://github.com/sylin-org/koi"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/sylin-org/koi/releases/download/v#{version}/koi-#{version}-aarch64-apple-darwin.tar.gz"
      # TODO(release): sha256 from the release manifest
      sha256 :TODO
    else
      url "https://github.com/sylin-org/koi/releases/download/v#{version}/koi-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 :TODO
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/sylin-org/koi/releases/download/v#{version}/koi-#{version}-aarch64-unknown-linux-musl.tar.gz"
      sha256 :TODO
    else
      url "https://github.com/sylin-org/koi/releases/download/v#{version}/koi-#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 :TODO
    end
  end

  def install
    bin.install "koi"
  end

  def caveats
    <<~EOS
      Run as a service:  sudo koi install      (systemd unit, Linux)
      Verify a build:    gh attestation verify <archive> --repo sylin-org/koi
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/koi --version")
  end
end
