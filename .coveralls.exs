# Coveralls configuration for Tango OAuth library
[
  # Coverage output directory
  output_dir: "cover/",
  
  # Template for coverage report
  template_path: "cover/excoveralls.html.eex",
  
  # Minimum coverage percentage required
  minimum_coverage: 85,
  
  # Files to exclude from coverage analysis
  skip_files: [
    # Test files
    "test/",
    
    # Generated files
    "lib/tango/application.ex",  # Boilerplate OTP application module
    
    # Mix tasks (if any)
    "lib/mix/tasks/",
    
    # Development utilities
    "lib/tango/test_repo.ex"     # Only used in testing
  ],
  
  # Coverage thresholds for different types of files
  coverage_options: [
    # Core business logic should have high coverage
    view_dirs: [],
    source_ref: "master",
    html_filter: &(Path.extname(&1) == ".ex")
  ],
  
  # Stop processing files when minimum coverage is not met
  halt_on_failure: false,
  
  # Coverage tracking options
  track_files: "lib/**/*.ex"
]