import { Menu, X } from "lucide-react";
import { useEffect, useState } from "react";

const navLinks = [
  { href: "#about", label: "About" },
  { href: "#projects", label: "Projects" },
  { href: "#experience", label: "Experience" },
  { href: "#testimonials", label: "Testimonials" },
];

export const Navbar = () => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50);
    };

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <header
      className={`fixed top-0 left-0 right-0 transition-all duration-500 ${
        isScrolled ? "glass-strong py-3" : "bg-transparent py-5"
      } z-50`}
    >
      <nav className="container mx-auto px-6 flex items-center justify-between">
        {/* LEFT – spacer (logo removed) */}
        <div className="w-10" />

        {/* CENTER – Nav links */}
        <div className="hidden md:flex items-center gap-1">
          <div className="glass rounded-full px-2 py-1 flex items-center gap-1">
            {navLinks.map((link, index) => (
              <a
                key={index}
                href={link.href}
                className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground rounded-full hover:bg-surface transition"
              >
                {link.label}
              </a>
            ))}
          </div>
        </div>


        {/* RIGHT – Profile Avatar + Badges */}
        <div className="relative z-50 hidden md:flex items-center">
          {/* Avatar */}
          <a href="#contact">
            <img
              src="/profile-photo.png"
              alt="Supam Roy"
              className="w-24 h-24 rounded-full object-cover border border-primary/40 ring-2 ring-primary/20 hover:scale-105 transition-transform"
            />
          </a>

          {/* 2+ Years Experience Badge */}
          <div className="absolute -top-4 -left-15 glass rounded-xl px-3 py-2 animate-float">
            <div className="text-lg font-bold text-primary">2+</div>
            <div className="text-xs text-muted-foreground">Years Exp.</div>
          </div>

          {/* Available for Work Badge */}
          <div className="absolute -bottom-4 -right-16 glass rounded-xl px-3 py-2 flex items-center gap-2 animate-float animation-delay-300">
            <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            <span className="text-xs font-medium">Available</span>
          </div>
        </div>

        {/* MOBILE MENU BUTTON */}
        <button
          className="md:hidden p-2 text-foreground cursor-pointer"
          onClick={() => setIsMobileMenuOpen((prev) => !prev)}
        >
          {isMobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
        </button>
      </nav>

      {/* MOBILE MENU */}
      {isMobileMenuOpen && (
        <div className="md:hidden glass-strong animate-fade-in">
          <div className="container mx-auto px-6 py-6 flex flex-col gap-4 text-center">
            {/* Mobile Avatar */}
            <div className="flex justify-center pb-4">
              <img
                src="/profile-avatar.jpg"
                alt="Supam Roy"
                className="w-32 h-32 rounded-full object-cover border border-primary/40 ring-2 ring-primary/20"
              />
            </div>

            {navLinks.map((link, index) => (
              <a
                key={index}
                href={link.href}
                onClick={() => setIsMobileMenuOpen(false)}
                className="text-lg text-muted-foreground hover:text-foreground py-2"
              >
                {link.label}
              </a>
            ))}
          </div>
        </div>
      )}
    </header>
  );
};
