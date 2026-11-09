if __name__ == "__main__":
    try:
        main()
    except PackageError as error:
        print(json.dumps({"packageError": str(error)}), file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print(json.dumps({"error": error.__class__.__name__}), file=sys.stderr)
        sys.exit(1)
