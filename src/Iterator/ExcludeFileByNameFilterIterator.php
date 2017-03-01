<?php

namespace OC\Signature\Iterator;

class ExcludeFileByNameFilterIterator extends \RecursiveFilterIterator {
	/**
	 * Array of excluded file names. Those are not scanned by the integrity checker.
	 * This is used to exclude files which administrators could upload by mistakes
	 * such as .DS_Store files.
	 *
	 * @var array
	 */
	private $excludedFilenames = [
		'.DS_Store', // Mac OS X
		'Thumbs.db', // Microsoft Windows
		'.directory', // Dolphin (KDE)
		'.webapp', // Gentoo/Funtoo & derivatives use a tool known as webapp-config to manager wep-apps.
	];

	/**
	 * @return bool
	 */
	public function accept() {
		if($this->isDir()) {
			return true;
		}

		return !in_array(
			$this->current()->getFilename(),
			$this->excludedFilenames,
			true
		);
	}
}
