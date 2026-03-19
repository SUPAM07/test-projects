const experiences = [
  {
    period: "January 2026 — April 2026",
    role: "Research Intern",
    company: "IISC Bangalore",
    description:
      "Contributed to a high-throughput C++17 Deep Packet Inspection engine that parses network packets and extracts TLS SNI for HTTPS classification, using a 16-thread flow-aware pipeline sustaining 470K+ packets/sec and improving throughput by 26% through optimized hashing.",
    technologies: [
      "C++17",
      "Multithreading (std::thread)",
      "Networking Protocols (Ethernet, IPv4, TCP/UDP)/UDP Packets",
      "Hashing Algorithms",
    ],
    current: true,
  },
  {
    period: "May 2025 — July 2025",
    role: "Software Engineering Intern",
    company: "Tailored AI",
    description:
      "Contributed to a semantic QA system for customer support using embedding-based retrieval, building a PDF ingestion and MiniLM indexing pipeline for 10K+ document segments and improving search accuracy while enabling Docker + GitHub Actions CI/CD deployment to AWS EC2.",
    technologies: [
      "Python",
      "MiniLM Embedding ",
      "Vector Search",
      " PDF Parsing",
      "Docker",
      "AWS EC2",
    ],
    current: false,
  },
  {
    period: "2023 — 2024",
    role: "Full Stack Developer (Projects)",
    company: "Personal & Open Source",
    description:
      "Built end-to-end products including an AI component generator and a computer vision–based Rubik’s Cube solver, focusing on performance, clean architecture, and developer experience.",
    technologies: [
      "React",
      "Vite",
      "Tailwind CSS",
      "Python",
      "OpenCV",
      "AWS",
    ],
    current: false,
  },
  {
    period: "2022 — Present",
    role: "B.Tech Student, Computer Science",
    company: "National Institute of Technology Durgapur",
    description:
      "Developing strong foundations in DSA, OOPS, DBMS, and Computer Networks. Solved 300+ DSA problems and actively participated in hackathons and technical projects.",
    technologies: ["C++", "Python", "DSA", "DBMS", "Computer Networks"],
    current: false,
  },
];

export const Experience = () => {
  return (
    <section id="experience" className="py-32 relative overflow-hidden">
      {/* Background Glow */}
      <div className="absolute top-1/2 left-1/4 w-96 h-96 bg-primary/5 rounded-full blur-3xl -translate-y-1/2" />

      <div className="container mx-auto px-6 relative z-10">
        {/* Section Header */}
        <div className="max-w-3xl mb-16">
          <span className="text-secondary-foreground text-sm font-medium tracking-wider uppercase animate-fade-in">
            Career Journey
          </span>

          <h2 className="text-4xl md:text-5xl font-bold mt-4 mb-6 animate-fade-in animation-delay-100 text-secondary-foreground">
            From foundations to{" "}
            <span className="font-serif italic font-normal text-white">
              real-world impact.
            </span>
          </h2>

          <p className="text-muted-foreground animate-fade-in animation-delay-200">
            A timeline of my growth as a computer science student, software
            engineering intern, and AI-focused developer building scalable
            systems and intelligent products.
          </p>
        </div>

        {/* Timeline */}
        <div className="relative">
          {/* Vertical Line */}
          <div className="timeline-glow absolute left-0 md:left-1/2 top-0 bottom-0 w-[2px] bg-gradient-to-b from-primary/70 via-primary/30 to-transparent md:-translate-x-1/2 shadow-[0_0_25px_rgba(32,178,166,0.8)]" />

          {/* Experience Items */}
          <div className="space-y-12">
            {experiences.map((exp, idx) => (
              <div
                key={idx}
                className="relative grid md:grid-cols-2 gap-8 animate-fade-in"
                style={{ animationDelay: `${(idx + 1) * 150}ms` }}
              >
                {/* Timeline Dot */}
                <div className="absolute left-0 md:left-1/2 top-0 w-3 h-3 bg-primary rounded-full -translate-x-1/2 ring-4 ring-background z-10">
                  {exp.current && (
                    <span className="absolute inset-0 rounded-full bg-primary animate-ping opacity-75" />
                  )}
                </div>

                {/* Content */}
                <div
                  className={`pl-8 md:pl-0 ${
                    idx % 2 === 0
                      ? "md:pr-16 md:text-right"
                      : "md:col-start-2 md:pl-16"
                  }`}
                >
                  <div className="glass p-6 rounded-2xl border border-primary/30 hover:border-primary/50 transition-all duration-500">
                    <span className="text-sm text-primary font-medium">
                      {exp.period}
                    </span>

                    <h3 className="text-xl font-semibold mt-2">
                      {exp.role}
                    </h3>

                    <p className="text-muted-foreground">
                      {exp.company}
                    </p>

                    <p className="text-sm text-muted-foreground mt-4">
                      {exp.description}
                    </p>

                    <div
                      className={`flex flex-wrap gap-2 mt-4 ${
                        idx % 2 === 0 ? "md:justify-end" : ""
                      }`}
                    >
                      {exp.technologies.map((tech, techIdx) => (
                        <span
                          key={techIdx}
                          className="px-3 py-1 bg-surface text-xs rounded-full text-muted-foreground"
                        >
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};
